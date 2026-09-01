/**
 * Session/turn-scoped guard state with TTL.
 *
 * Carries everything the stateful layer needs across events: repeat-call
 * counters, tool-call records (audit), script-artifact provenance, per-turn
 * data-egress legs, and session-scoped observed secrets + risk flags. Entries
 * expire via lazy cleanup on every accessor (no timers); `agent/disposed`
 * calls `clearSession` so a dead session's state can never be reused by a
 * fresh id.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/state-store
 */

/** How many identical mutating calls one turn may make before the repeat budget fires. */
export const REPEAT_CALL_BUDGET = 3
/** Default entry TTL (5 minutes); refreshed on every access (sliding). */
export const STATE_ENTRY_TTL_MS = 300_000
/** Upper bound on per-session observed secrets (insertion-order FIFO; evicts one entry per overflow). */
export const MAX_OBSERVED_SECRETS = 200

/** Cumulative data-egress legs observed in one session/turn. */
export interface GuardSignals {
  /** A credential is in play (secret referenced or observed). */
  credential: boolean
  /** An encoding step (base64/hex/…) was seen. */
  encoding: boolean
  /** An outbound network call was seen. */
  egress: boolean
  outboundCalls: number
  riskyArtifact: boolean
}

/** One script artifact written this turn. */
export interface ArtifactRecord {
  path: string
  /** djb2 hash of the content (identity check, not cryptographic). */
  hash: string
  /** Content tripped a risk signal (high-risk / obfuscation / outbound+secret). */
  risk: boolean
  /** Content references an outbound sink. */
  outbound: boolean
}

interface TurnState {
  repeats: Map<string, number>
  artifacts: ArtifactRecord[]
  signals: GuardSignals
  /** How many stop-steer continuations the guard forced this turn. */
  stopSteers: number
  expiresAt: number
}

/** Session/turn-scoped state store with lazy TTL cleanup. */
export class GuardStateStore {
  private readonly ttlMs: number
  private readonly sessions = new Map<string, Map<number, TurnState>>()
  private readonly sessionSecrets = new Map<string, { values: Set<string>; expiresAt: number }>()
  private readonly sessionRiskFlags = new Map<string, { flags: Set<string>; expiresAt: number }>()

  constructor(ttlMs = STATE_ENTRY_TTL_MS) {
    this.ttlMs = ttlMs
  }

  /** Remove expired entries (lazy; called by every accessor). */
  cleanup(): void {
    const now = Date.now()
    for (const [sessionKey, turns] of this.sessions) {
      for (const [turn, state] of turns) {
        if (state.expiresAt <= now) turns.delete(turn)
      }
      if (turns.size === 0) this.sessions.delete(sessionKey)
    }
    for (const [sessionKey, entry] of this.sessionSecrets) {
      if (entry.expiresAt <= now) this.sessionSecrets.delete(sessionKey)
    }
    for (const [sessionKey, entry] of this.sessionRiskFlags) {
      if (entry.expiresAt <= now) this.sessionRiskFlags.delete(sessionKey)
    }
  }

  /** Drop all state for one session (agent disposed). */
  clearSession(sessionKey: string): void {
    this.sessions.delete(sessionKey)
    this.sessionSecrets.delete(sessionKey)
    this.sessionRiskFlags.delete(sessionKey)
  }

  /** Drop everything (tests / session disposed). */
  clear(): void {
    this.sessions.clear()
    this.sessionSecrets.clear()
    this.sessionRiskFlags.clear()
  }

  private turnState(sessionKey: string, turn: number): TurnState {
    let turns = this.sessions.get(sessionKey)
    if (turns === undefined) {
      turns = new Map()
      this.sessions.set(sessionKey, turns)
    }
    let state = turns.get(turn)
    if (state === undefined) {
      state = {
        repeats: new Map(),
        artifacts: [],
        signals: { credential: false, encoding: false, egress: false, outboundCalls: 0, riskyArtifact: false },
        stopSteers: 0,
        expiresAt: Date.now() + this.ttlMs,
      }
      turns.set(turn, state)
    } else {
      // Sliding TTL: an actively-used session never loses its mid-turn state
      // mid-conversation, so multi-step exfil chains stay armed for as long as
      // the conversation is live (S6). Idle sessions still expire.
      state.expiresAt = Date.now() + this.ttlMs
    }
    return state
  }

  /** Touch a turn's expiry (called by the read accessors). */
  private touch(sessionKey: string, turn: number): void {
    const state = this.sessions.get(sessionKey)?.get(turn)
    if (state !== undefined) state.expiresAt = Date.now() + this.ttlMs
  }

  /** Count one more identical call for (session, turn, key); returns the new count. */
  countRepeat(sessionKey: string, turn: number, key: string): number {
    const state = this.turnState(sessionKey, turn)
    const count = (state.repeats.get(key) ?? 0) + 1
    state.repeats.set(key, count)
    return count
  }

  /** Increment the stop-steer counter for (session, turn); returns the new count. */
  incrementStopSteer(sessionKey: string, turn: number): number {
    const state = this.turnState(sessionKey, turn)
    state.stopSteers += 1
    return state.stopSteers
  }

  /** Record one script artifact written this turn. */
  noteArtifact(sessionKey: string, turn: number, artifact: ArtifactRecord): void {
    this.turnState(sessionKey, turn).artifacts.push(artifact)
  }

  /** Merge a partial patch into the turn's cumulative signals. */
  noteSignals(sessionKey: string, turn: number, patch: Partial<GuardSignals>): void {
    const state = this.turnState(sessionKey, turn)
    state.signals = { ...state.signals, ...patch }
  }

  /** Copy of the turn's cumulative signals, or `undefined`. */
  peekSignals(sessionKey: string, turn: number): GuardSignals | undefined {
    this.cleanup()
    this.touch(sessionKey, turn)
    const state = this.sessions.get(sessionKey)?.get(turn)
    return state === undefined ? undefined : { ...state.signals }
  }

  /** Copy of the turn's artifact records. */
  peekArtifacts(sessionKey: string, turn: number): readonly ArtifactRecord[] {
    this.cleanup()
    this.touch(sessionKey, turn)
    const state = this.sessions.get(sessionKey)?.get(turn)
    return state === undefined ? [] : [...state.artifacts]
  }

  /** Add observed secrets (session-scoped, LRU-capped). */
  noteSecrets(sessionKey: string, secrets: readonly string[]): void {
    this.cleanup()
    let entry = this.sessionSecrets.get(sessionKey)
    if (entry === undefined) {
      entry = { values: new Set(), expiresAt: Date.now() + this.ttlMs }
      this.sessionSecrets.set(sessionKey, entry)
    }
    // FIFO cap: a large directory listing must not drown the chain detector
    // (B4#9). Evict one oldest (insertion-first) entry per overflow (N8).
    entry.expiresAt = Date.now() + this.ttlMs
    for (const secret of secrets) {
      entry.values.add(secret)
      if (entry.values.size > MAX_OBSERVED_SECRETS) {
        const oldest = entry.values.values().next().value
        if (oldest !== undefined) entry.values.delete(oldest)
      }
    }
  }

  /** Session-scoped observed secrets. */
  peekSecrets(sessionKey: string): readonly string[] {
    this.cleanup()
    const entry = this.sessionSecrets.get(sessionKey)
    if (entry !== undefined) entry.expiresAt = Date.now() + this.ttlMs
    return entry === undefined ? [] : [...entry.values]
  }

  /** Add high-confidence risk flags from tool results (session-scoped). */
  noteRiskFlags(sessionKey: string, flags: readonly string[]): void {
    this.cleanup()
    let entry = this.sessionRiskFlags.get(sessionKey)
    if (entry === undefined) {
      entry = { flags: new Set(), expiresAt: Date.now() + this.ttlMs }
      this.sessionRiskFlags.set(sessionKey, entry)
    }
    entry.expiresAt = Date.now() + this.ttlMs
    for (const flag of flags) entry.flags.add(flag)
  }

  /** Session-scoped risk flags. */
  peekRiskFlags(sessionKey: string): readonly string[] {
    this.cleanup()
    const entry = this.sessionRiskFlags.get(sessionKey)
    if (entry !== undefined) entry.expiresAt = Date.now() + this.ttlMs
    return entry === undefined ? [] : [...entry.flags]
  }
}
