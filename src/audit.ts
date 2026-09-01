/**
 * Trajectory audit: records every guard verdict into a plugin-owned local
 * JSONL audit file so the security review survives restarts and can be folded
 * into a read value.
 *
 * Carrier choice (plugin-only constraint): the harness telemetry layer treats a
 * committed `feedback/record` event as the consent credential for exporting the
 * whole session (session-telemetry-otel). Reusing that event for guard verdicts
 * would turn a security plugin into a silent session exporter whenever the
 * deployment enables `FEEDBACK_ONLY` telemetry, and it would pollute the manual
 * feedback UI/statistics with machine-generated records. So verdicts are
 * written to the plugin's own audit file (`$DSH_HOME/agent-security-guard/
 * verdicts.jsonl`) instead, in the same directory with the same atomic-write discipline as
 * `effective.json`, and never enter the harness session log.
 *
 * Record policy: `allow` verdicts are NOT persisted by default (overwhelming
 * majority, low signal); `block` / `ask` / `warn` are. `allow` records can be
 * re-enabled via {@link VerdictRecorderOptions}. All writes are synchronous,
 * best-effort, and never throw into the guard's decision path.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/audit
 */

import { appendFileSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import type { GuardDecision, HookType, ModelReviewProvider, ModelReviewRecord } from './types.ts'
import { canonicalHook, hasApprovalSeam } from './hooks.ts'

/**
 * True when an `ask` verdict cannot wait on a human and is degraded by the
 * adapter (reject at `agent/pre-step`, block at `tools/post-execute`, steer at
 * `agent/turn-stopping`). The review rows then carry `noApprovalSeam` so the
 * panel labels reality.
 */
function askDegradedAt(hook: string): boolean {
  return !hasApprovalSeam(hook)
}

/** Everything needed to record one verdict. */
export interface VerdictRecord {
  hook: HookType
  /** The owner agent (harness agent id = session id). `undefined` degrades to a no-op. */
  sessionId?: string | undefined
  decision: GuardDecision
  tool?: string | undefined
  callId?: string | undefined
  turn?: number | undefined
  step?: number | undefined
  /**
   * The model-facing content the hook inspected (e.g. the assembled user
   * messages for `agent/pre-step`, the final assistant text for
   * `agent/turn-stopping`). Persisted on the verdict so the review
   * view does not have to re-derive it from the session log by turn/step
   * correlation, which can miss on continuation steps. Bounded by the caller.
   */
  content?: string | undefined
  /** Free-form annotation persisted on the row (e.g. a suppression note for
   * blocks withheld by the stop-steer cap). */
  note?: string | undefined
}

/** Options for {@link recordVerdict}. */
export interface VerdictRecorderOptions {
  /** Persist `allow` verdicts too (default `false`). */
  recordAllow?: boolean
}

/** One durable verdict line, as read back from the audit file. */
export interface StoredVerdict {
  v: number
  /** Per-process monotonically increasing ordinal (ordering ties by `time`). */
  seq: number
  /** Record time (ms). */
  time: number
  sessionId: string
  hook: string
  action: string
  outcome: string
  turn?: number
  step?: number
  tool?: string
  callId?: string
  policyId?: string
  message?: string
  content?: string
  /** Which review stage produced the final action: `rule` / `model` / `both`. */
  source?: string
  /** The model stage's verdict, when the model stage ran. */
  modelVerdict?: { action: string; reason: string; confidence?: number }
  /**
   * True when an `ask` verdict ran on a hook WITHOUT an approval seam
   * (`agent/pre-step` / `tools/post-execute`), so the adapter degraded
   * it to a reject/block instead of waiting on the human. The panel labels
   * such rows so "Awaiting confirmation" is never mistaken for a pending prompt.
   */
  noApprovalSeam?: boolean
  /**
   * Audit-row kind. Absent (or `'rule'`) = a merged rule-verdict row;
   * `'model'` = a dedicated model-review attempt row (see
   * {@link recordModelReview}). Legacy rows carry no `kind`.
   */
  kind?: 'rule' | 'model'
  /** Model-review attempt status (`'ok'` / `'error'` / `'skipped'`), `kind: 'model'` rows only. */
  modelStatus?: string
  /** Skip reason / make-up annotation (`modelStatus: 'skipped'` or `modelLate`). */
  note?: string
  /** True when this row is a post-hoc make-up review (audit-only, non-enforcing). */
  modelLate?: boolean
  /** Which model served the review request, `kind: 'model'` rows only. */
  provider?: ModelReviewProvider
  /** The rendered review prompt (request body), `kind: 'model'` rows only. */
  request?: string
  /** The model's raw output (response body), `kind: 'model'` rows only. */
  response?: string
  /** Wall-clock duration of the model call (ms), `kind: 'model'` rows only. */
  durationMs?: number
  /** Failure detail for a failed model-review attempt (`modelStatus: 'error'`). */
  error?: string
}

const PREFIX = '[agent-security-guard]'

/** Upper bound on one JSONL audit file before compaction (keeps the 4s poll bounded). */
const LOG_MAX_BYTES = 4 << 20

/** Per-process ordinal so rows have a stable, unique-enough id across appends. */
let seqCounter = 0

/** Directory creation memo (one real mkdir per process). */
let dirChecked = false

function ensureDir(dir: string): void {
  if (dirChecked) return
  try {
    mkdirSync(dir, { recursive: true })
  } catch {
    // logged by the caller on the first failed append
  }
  dirChecked = true
}

/**
 * Append one guard verdict to the plugin's local audit file. Failures are
 * logged, never thrown: auditing must not change the guard's decision behavior.
 * @param logPath absolute path to `verdicts.jsonl`; `undefined` disables.
 */
export function recordVerdict(ctx: Context, record: VerdictRecord, logPath: string | undefined, options: VerdictRecorderOptions = {}): void {
  if (logPath === undefined || record.sessionId === undefined) return
  if (record.decision.action === 'allow' && options.recordAllow !== true) return

  const outcome = record.decision.action === 'block' ? 'deny'
    : record.decision.action === 'ask' ? 'ask'
      : record.decision.action === 'warn' ? 'warn'
        : 'pass'

  const verdict: Record<string, unknown> = {
    v: 1,
    seq: (seqCounter += 1),
    time: Date.now(),
    sessionId: record.sessionId,
    hook: record.hook,
    action: record.decision.action,
    outcome,
  }
  if (record.turn !== undefined) verdict.turn = record.turn
  if (record.step !== undefined) verdict.step = record.step
  if (record.tool !== undefined) verdict.tool = record.tool
  if (record.callId !== undefined) verdict.callId = record.callId
  if (record.content !== undefined) verdict.content = record.content
  if (record.note !== undefined) verdict.note = record.note
  if (record.decision.policyId !== undefined) verdict.policyId = record.decision.policyId
  if (record.decision.message !== undefined) verdict.message = record.decision.message
  if (record.decision.source !== undefined) verdict.source = record.decision.source
  if (outcome === 'ask' && askDegradedAt(record.hook)) verdict.noApprovalSeam = true
  if (record.decision.modelVerdict !== undefined) {
    const mv = record.decision.modelVerdict
    verdict.modelVerdict = {
      action: mv.action,
      reason: mv.reason,
      ...(typeof mv.confidence === 'number' ? { confidence: mv.confidence } : {}),
    }
  }

  try {
    ensureDir(path.dirname(logPath))
    appendFileSync(logPath, `${JSON.stringify(verdict)}\n`, 'utf8')
    maybeCompact(logPath)
  } catch (error) {
    ctx.logger.warn(`${PREFIX} failed to record verdict for ${record.hook}: ${error instanceof Error ? error.message : String(error)}`)
  }
}

/** Options for {@link recordModelReview}. */
export interface ModelReviewRecorderOptions {
  /** Persist `allow` model-review rows too (default `false`). Error and
   * skipped rows (no verdict) are ALWAYS kept regardless — an unattempted or
   * failed review procedure must stay observable. */
  recordAllow?: boolean
}

/**
 * Append one model-review attempt to the plugin's local audit file (same
 * file, a `kind: 'model'` row). Written on EVERY attempt except that, like
 * merged verdicts, `allow` model rows follow {@link ModelReviewRecorderOptions#recordAllow}
 * (default `false`); `block` / `ask` / `warn`, `error` and `skipped` rows always
 * persist so the model stage's procedure stays observable. Failures are logged,
 * never thrown: auditing must not change the guard's decision behavior.
 * @param logPath absolute path to `verdicts.jsonl`; `undefined` disables.
 */
export function recordModelReview(ctx: Context, record: ModelReviewRecord, logPath: string | undefined, options: ModelReviewRecorderOptions = {}): void {
  if (logPath === undefined || record.sessionId === undefined) return
  if (record.action === 'allow' && options.recordAllow !== true) return

  const verdict: Record<string, unknown> = {
    v: 1,
    seq: (seqCounter += 1),
    time: Date.now(),
    sessionId: record.sessionId,
    hook: record.hook,
    kind: 'model',
    modelStatus: record.status,
  }
  if (record.turn !== undefined) verdict.turn = record.turn
  if (record.step !== undefined) verdict.step = record.step
  if (record.tool !== undefined) verdict.tool = record.tool
  if (record.callId !== undefined) verdict.callId = record.callId
  if (record.action !== undefined) {
    verdict.action = record.action
    verdict.outcome = record.action === 'block' ? 'deny'
      : record.action === 'ask' ? 'ask'
        : record.action === 'warn' ? 'warn'
          : 'pass'
    if (verdict.outcome === 'ask' && askDegradedAt(record.hook)) verdict.noApprovalSeam = true
  }
  if (record.reason !== undefined) verdict.message = record.reason
  if (record.error !== undefined) verdict.error = record.error
  // The message column carries whatever is most informative: the parsed
  // reason on ok rows, the failure detail on error rows, the skip reason on
  // skipped rows.
  if (verdict.message === undefined && record.error !== undefined) verdict.message = record.error
  if (verdict.message === undefined && record.note !== undefined) verdict.message = record.note
  if (record.note !== undefined) verdict.note = record.note
  if (record.late === true) verdict.modelLate = true
  if (record.provider !== undefined) verdict.provider = record.provider
  if (record.request !== undefined) verdict.request = record.request
  if (record.response !== undefined) verdict.response = record.response
  if (record.durationMs !== undefined) verdict.durationMs = record.durationMs

  try {
    ensureDir(path.dirname(logPath))
    appendFileSync(logPath, `${JSON.stringify(verdict)}\n`, 'utf8')
    maybeCompact(logPath)
  } catch (error) {
    ctx.logger.warn(`${PREFIX} failed to record model review for ${record.hook}: ${error instanceof Error ? error.message : String(error)}`)
  }
}

/**
 * Bound the audit file's growth: when it exceeds {@link LOG_MAX_BYTES}, rewrite
 * it keeping only the NEWEST half. Called opportunistically from the append
 * path (size check per direct append, which is already a syscall).
 */
function maybeCompact(logPath: string): void {
  let size: number
  try {
    size = statSync(logPath).size
  } catch {
    return
  }
  if (size <= LOG_MAX_BYTES) return
  let lines: string[]
  try {
    lines = readFileSync(logPath, 'utf8').split('\n')
  } catch {
    return
  }
  lines = lines.filter((line) => line.trim().length > 0)
  const keep = lines.slice(Math.floor(lines.length / 2))
  try {
    const tmp = `${logPath}.tmp`
    writeFileSync(tmp, `${keep.join('\n')}\n`, 'utf8')
    renameSync(tmp, logPath)
  } catch (error) {
    // best-effort; the file simply stays over budget until the next compaction
  }
}

/** Structural check for a persisted {@link ModelReviewProvider}. */
function isProviderOf(value: unknown): value is ModelReviewProvider {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const record = value as { mode?: unknown; provider?: unknown; model?: unknown; baseUrl?: unknown }
  if (record.mode !== 'session' && record.mode !== 'custom') return false
  if (record.provider !== undefined && typeof record.provider !== 'string') return false
  if (record.model !== undefined && typeof record.model !== 'string') return false
  if (record.baseUrl !== undefined && typeof record.baseUrl !== 'string') return false
  return true
}

/** Read every durable verdict line (oldest first); malformed lines are skipped. */
export function readVerdictLog(logPath: string): StoredVerdict[] {
  let text: string
  try {
    text = readFileSync(logPath, 'utf8')
  } catch {
    return []
  }
  const rows: StoredVerdict[] = []
  for (const line of text.split('\n')) {
    if (line.trim() === '') continue
    try {
      const parsed = JSON.parse(line) as Partial<StoredVerdict>
      if (parsed && typeof parsed === 'object' && typeof parsed.sessionId === 'string' && typeof parsed.hook === 'string') {
        rows.push({
          v: parsed.v ?? 1,
          seq: typeof parsed.seq === 'number' ? parsed.seq : rows.length,
          time: typeof parsed.time === 'number' ? parsed.time : 0,
          sessionId: parsed.sessionId,
          // Legacy rows carry the pre-native hook names; canonicalize on read
          // so every consumer (panel filters, grouping) sees native seams.
          hook: canonicalHook(parsed.hook),
          action: String(parsed.action ?? ''),
          outcome: String(parsed.outcome ?? ''),
          ...(typeof parsed.turn === 'number' ? { turn: parsed.turn } : {}),
          ...(typeof parsed.step === 'number' ? { step: parsed.step } : {}),
          ...(typeof parsed.tool === 'string' ? { tool: parsed.tool } : {}),
          ...(typeof parsed.callId === 'string' ? { callId: parsed.callId } : {}),
          ...(typeof parsed.policyId === 'string' ? { policyId: parsed.policyId } : {}),
          ...(typeof parsed.message === 'string' ? { message: parsed.message } : {}),
          ...(typeof parsed.content === 'string' ? { content: parsed.content } : {}),
          ...(typeof parsed.source === 'string' ? { source: parsed.source } : {}),
          ...(parsed.kind === 'model' || parsed.kind === 'rule' ? { kind: parsed.kind } : {}),
          ...(parsed.noApprovalSeam === true ? { noApprovalSeam: true } : {}),
          ...(typeof parsed.modelStatus === 'string' ? { modelStatus: parsed.modelStatus } : {}),
          ...(typeof parsed.note === 'string' ? { note: parsed.note } : {}),
          ...(parsed.modelLate === true ? { modelLate: true } : {}),
          ...(typeof parsed.durationMs === 'number' ? { durationMs: parsed.durationMs } : {}),
          ...(typeof parsed.error === 'string' ? { error: parsed.error } : {}),
          ...(typeof parsed.request === 'string' ? { request: parsed.request } : {}),
          ...(typeof parsed.response === 'string' ? { response: parsed.response } : {}),
          ...(isProviderOf(parsed.provider) ? { provider: parsed.provider } : {}),
          ...(typeof parsed.modelVerdict === 'object' && parsed.modelVerdict !== null
            ? (() => {
                const mv = parsed.modelVerdict as { action?: unknown; reason?: unknown; confidence?: unknown }
                if (typeof mv.action === 'string' && typeof mv.reason === 'string') {
                  const out: StoredVerdict['modelVerdict'] = { action: mv.action, reason: mv.reason }
                  if (typeof mv.confidence === 'number') out.confidence = mv.confidence
                  return { modelVerdict: out }
                }
                return {}
              })()
            : {}),
        })
      }
    } catch {
      // skip malformed / half-written lines (crash tolerance)
    }
  }
  return rows
}

/**
 * Truncate the audit file (the panel's "Clear log" action). Replace keeps the
 * same directory and atomic-write discipline as `effective.json`.
 */
export function clearVerdictLog(logPath: string): void {
  try {
    const tmp = `${logPath}.tmp`
    writeFileSync(tmp, '', 'utf8')
    renameSync(tmp, logPath)
  } catch {
    // best-effort: an unwritable file keeps serving stale rows
  }
}

/**
 * The current turn number, derived from the last `turn/start` in the session
 * log (tool hooks carry no turn in their payload).
 */
export function currentTurn(session: { events: readonly unknown[] } | undefined): number | undefined {
  if (session === undefined) return undefined
  const events = session.events
  for (let i = events.length - 1; i >= 0; i--) {
    const event = events[i] as { type?: unknown; data?: { turn?: unknown } } | undefined
    if (event?.type === 'turn/start') {
      return typeof event.data?.turn === 'number' ? event.data.turn : undefined
    }
  }
  return undefined
}