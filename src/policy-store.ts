/**
 * Policy file bus: the bridge between the browser panel and the engine.
 *
 * Layout (all under `policyStoreDir()`):
 *
 *   ui-policies.json: written either by a human editing the file, or on
 *                       behalf of the panel's dynamic host half, by THIS
 *                       module's {@link PolicyFileStore.writeUiPolicies} using
 *                       native fs (the vm host half cannot reach node:fs, and
 *                       the cordis fs service it otherwise uses is confined to
 *                       the session workspace, which this per-user config dir
 *                       is outside of).
 *   effective.json: written by this module. This is the CURRENT effective table
 *                       (source, version, policies, last sync error), which
 *                       the host half serves to the panel read-only.
 *
 * Semantics: presence of a valid `ui-policies.json` REPLACES the cordis.yml
 * policies wholesale (no merging); its removal, or a `{v:1, reset:true}`
 * marker, restores the cordis.yml baseline. Invalid content never touches
 * the engine: the last good table stays live and the error is mirrored into
 * `effective.json` so the panel can show why a save did not take effect.
 *
 * The engine swap is a reference assignment (`GuardEngine.setPolicies`);
 * `decide` is a synchronous pure function, so a swap mid-event-loop is safe.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/policy-store
 */

import { mkdirSync, readFileSync, renameSync, unlinkSync, watchFile, unwatchFile, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { UiPolicyTable, validatePolicies } from './config.ts'
import type { GuardPolicy } from './types.ts'
import type { GuardEngine } from './engine.ts'

/** Subdirectory under DSH_HOME owning both bus files. */
const SUBDIR = 'agent-security-guard'

export const UI_POLICIES_FILE = 'ui-policies.json'
export const EFFECTIVE_FILE = 'effective.json'

/** Where both bus files live: `$DSH_HOME/agent-security-guard` (default `~/.dsh`). */
export function policyStoreDir(): string {
  const envHome = process.env.DSH_HOME?.trim()
  const home = envHome && envHome.length > 0 ? envHome : path.join(os.homedir(), '.dsh')
  return path.join(home, SUBDIR)
}

export const VERDICT_LOG_FILE = 'verdicts.jsonl'

export interface PolicyStorePaths {
  dir: string
  uiPoliciesPath: string
  effectivePath: string
  /** Plugin-owned verdict audit trail (JSONL), see audit.ts. */
  verdictLogPath: string
}

/** Resolve the bus file paths (the host code bakes these in at `define` time). */
export function policyStorePaths(): PolicyStorePaths {
  const dir = policyStoreDir()
  return {
    dir,
    uiPoliciesPath: path.join(dir, UI_POLICIES_FILE),
    effectivePath: path.join(dir, EFFECTIVE_FILE),
    verdictLogPath: path.join(dir, VERDICT_LOG_FILE),
  }
}

/** Structural logger (satisfied by `ctx.logger`). */
export interface PolicyStoreLogger {
  info(message: string): void
  warn(message: string): void
  debug?(message: string): void
}

export interface PolicyStoreOptions {
  /** Directory holding both bus files; created (best-effort) on `start`. */
  dir: string
  /** The cordis.yml policies the engine was constructed with. */
  basePolicies: readonly GuardPolicy[]
  /** Live engine to swap tables into. */
  engine: GuardEngine
  logger: PolicyStoreLogger
  /** `watchFile` poll interval in ms (default 500; small in tests). */
  watchIntervalMs?: number
}

export type PolicySource = 'cordis.yml' | 'ui-policies.json'

/** Snapshot of what is currently enforced (and why it is not, when broken). */
export interface PolicyStoreState {
  source: PolicySource
  /** Engine swap counter (0 = constructor table untouched). */
  version: number
  policies: readonly GuardPolicy[]
  /** Present when the last sync of `ui-policies.json` failed. */
  error?: string
}

const PREFIX = '[agent-security-guard]'

/**
 * Schemastery's `validate` is synchronous even though the Standard Schema
 * spec's signature permits a promise; name the sync shape once so callers
 * can narrow `issues` / `value` without a promise branch.
 */
type SyncValidateResult<T> =
  | { value: T; issues?: undefined }
  | { issues: ReadonlyArray<{ message: string; path?: ReadonlyArray<PropertyKey | { key: PropertyKey }> }> }

/** Whether the last file read was a valid, applied table (content-deduped). */
function isEnoent(error: unknown): boolean {
  return (error as NodeJS.ErrnoException | undefined)?.code === 'ENOENT'
}

function messageOf(error: unknown): string {
  try {
    return error instanceof Error ? error.message : String(error)
  } catch {
    return '<unprintable error>'
  }
}

export class PolicyFileStore {
  readonly uiPoliciesPath: string
  readonly effectivePath: string
  private readonly dir: string
  private readonly basePolicies: readonly GuardPolicy[]
  private readonly engine: GuardEngine
  private readonly logger: PolicyStoreLogger
  private readonly watchIntervalMs: number
  /** Last `ui-policies.json` content processed (any kind of parse result). */
  private lastRaw: string | undefined
  /** The table currently enforced, tracked for no-op skipping. */
  private current: { source: PolicySource; policies: readonly GuardPolicy[] }
  private lastError: string | undefined

  constructor(options: PolicyStoreOptions) {
    this.dir = options.dir
    this.basePolicies = options.basePolicies
    this.engine = options.engine
    this.logger = options.logger
    this.watchIntervalMs = options.watchIntervalMs ?? 500
    this.uiPoliciesPath = path.join(options.dir, UI_POLICIES_FILE)
    this.effectivePath = path.join(options.dir, EFFECTIVE_FILE)
    // `apply` constructs the engine FROM `basePolicies`, so at construction
    // the baseline is already enforced. No swap needed unless a file says
    // otherwise.
    this.current = { source: 'cordis.yml', policies: options.basePolicies }
  }

  /** Ensure the directory, load any existing file, start watching. Idempotent-ish: one watcher per store. */
  start(): void {
    try {
      mkdirSync(this.dir, { recursive: true })
    } catch (error) {
      this.logger.warn(`${PREFIX} policy store: cannot create ${this.dir}: ${messageOf(error)} (baseline policies stay in effect)`)
    }
    this.sync()
    watchFile(this.uiPoliciesPath, { interval: this.watchIntervalMs }, () => this.sync())
  }

  /** Stop watching (effective.json and loaded state are left in place). */
  stop(): void {
    unwatchFile(this.uiPoliciesPath)
  }

  /** Current enforced table + provenance (never throws). */
  state(): PolicyStoreState {
    const state: PolicyStoreState = {
      source: this.current.source,
      version: this.engine.version,
      policies: this.current.policies,
    }
    if (this.lastError !== undefined) state.error = this.lastError
    return state
  }

  /**
   * Read + validate + apply `ui-policies.json` once. Safe to call from the
   * watcher, at startup, or manually (tests). Never throws: failures are
   * logged and mirrored into `effective.json`, the engine keeps the last
   * good table.
   */
  sync(): void {
    let raw: string
    try {
      raw = readFileSync(this.uiPoliciesPath, 'utf8')
    } catch (error) {
      if (isEnoent(error)) {
        // The file was removed. Forget the last content seen so that
        // re-creating it with identical content re-applies (the `raw ===
        // lastRaw` dedup must not swallow a fresh application, M1).
        this.lastRaw = undefined
        this.applyBase()
        return
      }
      // Transient (permissions mid-rename, …): keep the current table.
      this.logger.debug?.(`${PREFIX} policy store: cannot read ${this.uiPoliciesPath}: ${messageOf(error)}`)
      return
    }
    if (raw === this.lastRaw) return
    this.lastRaw = raw

    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch (error) {
      this.reportError(`ui-policies.json is not valid JSON: ${messageOf(error)}`)
      return
    }
    const result = UiPolicyTable['~standard'].validate(parsed) as SyncValidateResult<UiPolicyTable>
    if (result.issues) {
      const first = result.issues[0]
      if (!first) {
        this.reportError('ui-policies.json failed schema validation (no details)')
        return
      }
      const where = first.path?.length ? ` (at path ${JSON.stringify(first.path)})` : ''
      this.reportError(`ui-policies.json failed schema validation${where}: ${first.message}`)
      return
    }
    const table = result.value
    try {
      validatePolicies(table.policies)
    } catch (error) {
      this.reportError(`ui-policies.json failed semantic validation: ${messageOf(error)}`)
      return
    }
    if (table.reset) {
      this.applyBase()
      this.removeUiFile()
      return
    }
    this.applyTable(table.policies)
  }

  /** Restore (or re-affirm) the cordis.yml baseline table. */
  private applyBase(): void {
    if (this.current.source !== 'cordis.yml' || this.current.policies !== this.basePolicies) {
      this.engine.setPolicies(this.basePolicies)
      this.current = { source: 'cordis.yml', policies: this.basePolicies }
    }
    this.lastError = undefined
    this.writeEffective()
    this.logger.info(`${PREFIX} policy store: effective table = cordis.yml baseline (${this.basePolicies.length} policies, version ${this.engine.version})`)
  }

  /** Swap the validated UI table into the engine. */
  private applyTable(policies: readonly GuardPolicy[]): void {
    if (this.current.source === 'ui-policies.json' && this.current.policies === policies) {
      this.lastError = undefined
      this.writeEffective()
      return
    }
    this.engine.setPolicies(policies)
    this.current = { source: 'ui-policies.json', policies }
    this.lastError = undefined
    this.writeEffective()
    this.logger.info(`${PREFIX} policy store: effective table = ui-policies.json (${policies.length} policies, version ${this.engine.version})`)
  }

  /** Keep the last good table live; record the failure in `effective.json`. */
  private reportError(error: string): void {
    this.lastError = error
    this.logger.warn(`${PREFIX} policy store: ${error} — keeping the last good table (${this.current.source})`)
    this.writeEffective()
  }

  /** Best-effort delete after a reset marker; the baseline is already applied. */
  private removeUiFile(): void {
    try {
      unlinkSync(this.uiPoliciesPath)
    } catch (error) {
      if (isEnoent(error)) return
      this.logger.warn(`${PREFIX} policy store: cannot remove ${this.uiPoliciesPath}: ${messageOf(error)}`)
    }
  }

  /** Atomically mirror the current state into `effective.json` (panel read path). */
  private writeEffective(): void {
    const payload: Record<string, unknown> = {
      v: 1,
      source: this.current.source,
      version: this.engine.version,
      updated: Date.now(),
      policies: this.current.policies,
    }
    if (this.lastError !== undefined) payload.error = this.lastError
    try {
      const tmp = `${this.effectivePath}.tmp`
      writeFileSync(tmp, `${JSON.stringify(payload, null, 2)}\n`, 'utf8')
      renameSync(tmp, this.effectivePath)
    } catch (error) {
      // The panel degrades to "not ready"; the guard itself is unaffected.
      this.logger.warn(`${PREFIX} policy store: cannot write ${this.effectivePath}: ${messageOf(error)}`)
    }
  }

  /**
   * Write the UI policy table to `ui-policies.json` for the panel's host half,
   * using the SAME native atomic write as {@link writeEffective} (tmp + rename,
   * so the watcher never observes a partial file). The watcher, the single
   * ingestion point for this file, picks it up and {@link sync} applies it
   * within the poll interval, exactly as if a human had edited the file.
   *
   * The target path is FIXED to this store's `uiPoliciesPath`: the method takes
   * only serialized content, never a path, so callers (including the vm host
   * half, which otherwise cannot reach node:fs) can never write to an
   * arbitrary location through this bridge. This is deliberate: it lets the
   * panel persist its own config file under `$DSH_HOME/agent-security-guard`
   * (outside the session workspace the sandboxed fs service confines writes
   * to) without handing it any broader filesystem authority.
   *
   * @param content - the serialized table (the host half has already
   *   validated its shape; `sync` re-validates schema + semantics before the
   *   engine swaps, so invalid content never takes effect).
   * @throws when the native write or rename fails. The host half surfaces
   *   this to the panel as the save error.
   */
  writeUiPolicies(content: string): void {
    try {
      const tmp = `${this.uiPoliciesPath}.tmp`
      writeFileSync(tmp, content, 'utf8')
      renameSync(tmp, this.uiPoliciesPath)
    } catch (error) {
      throw new Error(`cannot write ${this.uiPoliciesPath}: ${messageOf(error)}`)
    }
  }
}
