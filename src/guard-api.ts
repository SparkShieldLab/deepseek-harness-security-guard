/**
 * Host-side HTTP API for the Security-Guard Review panel.
 *
 * This is the static-web replacement for the dynamic plugin's vm-sandbox host
 * half (the old `buildHostCode` in ui.ts). The panel client, now a static
 * client bundle (`dsh.client.inject`) loaded by the web shell at boot, calls
 * these routes with `fetch`, so:
 *
 *   - no `dynamicCordisRunner` is involved: no per-process approval, no
 *     session anchoring, no `agent.steer` status message;
 *   - the host half runs in the MAIN plugin (harness process) with full
 *     `node:fs`, so the read/write paths no longer need the sandboxed cordis
 *     `fs` service or the vm-safe write bridge. `PolicyFileStore` still owns
 *     the write (same code path as effective.json, watcher-hot-reloaded).
 *
 * Verdict source: the plugin's own JSONL audit file (`verdicts.jsonl`,
 * `audit.ts`), never the harness session log. The `feedback/record` event is
 * deliberately NOT used because the harness telemetry layer treats it as the
 * consent credential for exporting the whole session (B1).
 *
 * Route/authn summary (wire protocol identical to the old `harness.handle`
 * handlers, so the client semantics did not change, only the transport and
 * the security envelope):
 *
 *   GET  /guard/api/verdicts        → verdict rows (folded from the audit file
 *                                     + live-session context; `?sessionId=`
 *                                     narrows, `?after=<seq>` returns newer rows only)
 *   POST /guard/api/clear-verdicts  → { ok, message } (truncates the audit file)
 *   GET  /guard/api/policies        → { ok, data } | { ok:false, error }
 *   POST /guard/api/policies        → { ok, message } | { ok:false, error }
 *   POST /guard/api/reset-policies  → { ok, message } | { ok:false, error }
 *   GET  /guard/api/lang            → { locale } ('auto' | 'zh' | 'en')
 *   POST /guard/api/lang            → { ok, message, locale }
 *   POST /guard/api/lang/resolved   → { ok } (in-memory DSH locale seed for auto mode)
 *   GET  /guard/api/prefs           → { locale, showSessionTab, showHeaderButton, guardEnabled }
 *   POST /guard/api/prefs           → { ok, message, locale, showSessionTab, showHeaderButton, guardEnabled }
 *
 * Security envelope (all routes):
 *   - loopback-only `Host` (DNS-rebinding fence), incl. correct IPv6 `[::1]`,
 *     UNION the explicit `webRuntime.trustedHosts` allowlist (the DSH Web
 *     runtime's bind-derived LAN literals plus any `dsh web --trusted-host`
 *     authorities). Loopback stays accepted even when a whitelist is present
 *     (the local URL must keep working), so the allowlist only ever *widens*
 *     the fence, never narrows it;
 *   - cross-site browser fetches are rejected (`Sec-Fetch-Site`);
 *   - a mismatched `Origin` is rejected (hostname must be loopback or in the
 *     allowlist, and match the request Host);
 *   - every mutation additionally requires a `Content-Type: application/json`
 *     body (blocking CORS-safelisted "simple request" CSRF) AND a per-process
 *     unpredictable CSRF token delivered as a `SameSite=Strict` cookie issued
 *     by the first panel response (double-submit; a cross-site page never
 *     carries it, so the mutation is refused).
 *   - when the webServer binds a NON-loopback host (`0.0.0.0`), the panel API
 *     is NOT registered unless a `webRuntime.trustedHosts` allowlist exists
 *     (`--trusted-host`, or the bind-derived LAN literals of an all-interfaces
 *     assembly). With no allowlist, no session plaintext or control route is
 *     ever exposed to the network (upstream `dsh web` refuses `--host 0.0.0.0`
 *     itself; this makes a custom Cordis assembly safe too).
 *
 * Every route answers JSON; failures are written as HTTP 500 + an
 * `{ ok:false, error:{code,message} }` envelope and never thrown outward
 * (a request whose handling throws is answered 400 by the webServer).
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/guard-api
 */

import { randomBytes } from 'node:crypto'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { readFileSync } from 'node:fs'
import type { Context } from '@deepseek-ai/cordis'
import type { PolicyStorePaths } from './policy-store.ts'
import type { GuardPrefs, ModelReviewPrefs, ReviewPromptTemplate } from './config.ts'
import { BASELINE_REVIEW_TEMPLATES } from './audit-prompts.ts'
import { canonicalHook, POLICY_HOOKS } from './hooks.ts'
import { clearVerdictLog, readVerdictLog } from './audit.ts'
import type { StoredVerdict } from './audit.ts'

/** Structural mirror of the webServer `register` route (host-webserver WebRoute). */
export interface GuardWebRoute {
  kind: 'exact' | 'prefix'
  path: string
  handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>
}

/** Structural mirror of the webServer service (host-webserver WebServer). */
export interface GuardWebServer {
  register(route: GuardWebRoute): () => void
  /**
   * The configured listen host (`'127.0.0.1' | '0.0.0.0'`). Present on the
   * real service. A non-loopback literal only registers when the DSH Web
   * runtime has supplied a `trustedHosts` allowlist; without one the plugin
   * refuses to expose the panel to the network.
   */
  host?: '127.0.0.1' | '0.0.0.0'
}

/** What the panel API needs from the main plugin. */
export interface GuardApiDeps {
  /** Absolute bus-file paths (`ui-policies.json` / `effective.json` / `verdicts.jsonl`). */
  paths: PolicyStorePaths
  /**
   * Persist a validated policy-table payload to `ui-policies.json` (fixed
   * path, atomic tmp+rename, watcher-hot-reloaded). Same bridge as before;
   * only the read path switched from the cordis fs service to native fs.
   */
  writeUiPolicies(content: string): void
  /**
   * Read the resolved language preference from the DSH settings namespace
   * (`agent-security-guard`); the schema default (`auto`) when the settings
   * service is absent.
   */
  getPrefs(): GuardPrefs
  /**
   * Merge a language preference into the DSH settings namespace user layer.
   * Resolves only through a registered settings provider; throws otherwise.
   */
  updatePrefs(patch: Partial<GuardPrefs>): Promise<void>
  /**
   * Resolve the panel language for user-visible messages: the explicit
   * `zh`/`en` preference, or (via `/guard/api/lang/resolved`) the effective DSH
   * locale last reported by the panel client so `auto` follows the host locale.
   * Falls back to the persisted preference when the client has not reported.
   */
  lang(): 'zh' | 'en'
  /**
   * Record the panel client's effective locale (resolved from the DSH locale
   * service + preference) so host-generated messages follow it. In-memory;
   * the client re-reports on boot and on any locale change.
   */
  reportResolvedLocale(locale: 'zh' | 'en'): void
}

const PREFIX = '[agent-security-guard]'

/** Body size bound of one JSON request (defense against unbounded reads). */
const MAX_BODY_BYTES = 1 << 20

/** Per-row context detail cap (chars) shipped to the panel; keeps the 4s poll bounded. */
const DETAIL_CAP = 4000

/** Name of the double-submit CSRF cookie / token the plugin issues at startup. */
const CSRF_COOKIE = 'dsh_guard_csrf'

/**
 * An empty review prompt means "use the built-in template" at review time.
 * Normalize so the persisted settings always carry the VISIBLE default: the
 * settings panel shows exactly what the model stage would use, and an
 * already-persisted empty prompt reads back as the template on the next open.
 */
/** Upper bound on custom review templates persisted through the prefs patch. */
const MAX_REVIEW_TEMPLATES = 64

/** The guard actions a template disposition cap may take (the same set the
 * engine's verdict severity table covers). */
const TEMPLATE_ACTIONS = ['allow', 'block', 'ask', 'warn'] as const

/**
 * The guard hooks a baseline/custom review template can bind to — every native
 * harness seam (the same surface the policy editor offers). At the
 * observe-only lifecycle seams the review runs as audit-only (the full
 * pipeline is registered there); `tools/guard` is synchronous and rule-stage
 * only, so a model binding there is inert.
 */
const HOOK_OPTIONS = POLICY_HOOKS
type ReviewTemplateHook = (typeof HOOK_OPTIONS)[number]

/** The loopback hosts the panel API may be opened from. */
function hostnameOfHost(host: unknown): string {
  if (typeof host !== 'string') return ''
  const h = host.trim().toLowerCase()
  if (h.startsWith('[')) {
    const end = h.indexOf(']')
    return end === -1 ? h.slice(1) : h.slice(1, end)
  }
  return h.split(':')[0] ?? ''
}

/** Full authority (`host [:port]`) of a request Host header, port-preserving;
 * returns `undefined` when the host carries no explicit port. */
function authorityOfHost(host: unknown): string | undefined {
  if (typeof host !== 'string') return undefined
  const h = host.trim().toLowerCase()
  if (h.startsWith('[')) {
    // IPv6 literal: bracket form may or may not carry a port (`[::1]` vs `[::1]:3080`).
    return /:[0-9]+\]$/.test(h) ? h : undefined
  }
  const idx = h.indexOf(':')
  return idx === -1 ? undefined : h.slice(idx + 1).length > 0 ? h : undefined
}

/** Whether a hostname is a loopback address (localhost, ::1, or 127.0.0.0/8). */
function isLoopbackName(name: string): boolean {
  if (name === 'localhost' || name === '::1') return true
  const parts = name.split('.')
  return parts.length === 4 && parts[0] === '127'
    && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}

/** DNS-rebinding / forged-Host fence: only loopback hosts may reach the panel API. */
function isLoopback(req: IncomingMessage): boolean {
  return isLoopbackName(hostnameOfHost(req.headers.host))
}

/**
 * Structural mirror of the DSH Web runtime's trust snapshot
 * (`@deepseek-ai/dsh-web-app` `webRuntime`, provided by bundle/web-app).
 * Only `trustedHosts` is consumed here (the [/]api browser-trust fence).
 */
export interface GuardWebRuntime {
  /** LAN IPv4 literals (bind-derived) + explicit `--trusted-host` authorities, in argument order. */
  trustedHosts: ReadonlyArray<string>
}

/** Structural mirror of `@deepseek-ai/dsh-web-app` `resolveLanTrust` defaults. */
function trustedHostsOf(ctx: Context): ReadonlyArray<string> {
  try {
    const runtime = ctx.get('webRuntime') as GuardWebRuntime | undefined
    if (runtime !== undefined && Array.isArray(runtime.trustedHosts)) return runtime.trustedHosts
  } catch {
    // webRuntime never provided (no web shell): no allowlist → loopback-only.
  }
  return EMPTY_TRUSTED_HOSTS
}

const EMPTY_TRUSTED_HOSTS: ReadonlyArray<string> = []

/**
 * Normalize a trustedHost entry to a matchable authority.
 * `dsh web --trusted-host` accepts `host` or `host:port`; bind-derived LAN
 * literals arrive port-less IPs. Any entry is matched against the request
 * authority in the same form the entry was given:
 *   - a port-less entry (`192.168.1.5`, `lab.internal`) matches any port
 *     (DNS-rebinding is name-based, and an IP-literal Host is safe on any
 *     port — see upstream `resolveLanTrust`);
 *   - a `host:port` entry matches only that precise authority.
 * Loopback matching is untouched and subsumes these (localhost/127/::1).
 */
function matchesTrustedHost(host: unknown, trusted: ReadonlyArray<string>): boolean {
  if (typeof host !== 'string' || trusted.length === 0) return false
  const h = host.trim().toLowerCase()
  for (const entry of trusted) {
    const e = entry.trim().toLowerCase()
    if (authorityOfHost(e) === undefined) {
      // Port-less entry: hostname equality is enough (any request port).
      if (hostnameOfHost(h) === hostnameOfHost(e)) return true
    } else if (h === e) {
      // Entry carries a port: require the exact authority (host:port).
      return true
    }
  }
  return false
}

/** Whether `name` is a trusted hostname (any entry whose host part equals it),
 * ignoring ports — used to validate the Origin hostname against the allowlist. */
function isTrustedHostname(name: string, trusted: ReadonlyArray<string>): boolean {
  const n = name.trim().toLowerCase()
  for (const entry of trusted) {
    const e = entry.trim().toLowerCase()
    if (hostnameOfHost(e) === n) return true
  }
  return false
}

/** Content-Type must be `application/json` when the request carries a body. */
function expectsBody(req: IncomingMessage): boolean {
  const length = Number(req.headers['content-length'] ?? 0)
  if (length > 0) return true
  const te = req.headers['transfer-encoding']
  return typeof te === 'string' && te.length > 0
}

function isJsonContentType(req: IncomingMessage): boolean {
  const ct = req.headers['content-type']
  return typeof ct === 'string' && ct.toLowerCase().startsWith('application/json')
}

/** Parse the optional `?sessionId=` / `?after=` query parameters. */
function queryParam(req: IncomingMessage, key: string): string | undefined {
  const raw = req.url ?? ''
  const q = raw.indexOf('?')
  if (q === -1) return undefined
  const value = new URLSearchParams(raw.slice(q + 1)).get(key)
  return value === null ? undefined : value
}

/** Narrow verdict rows to one session id (a no-filter read keeps every row). */
function filterVerdicts(rows: unknown[], sessionId: string | undefined): unknown[] {
  if (sessionId === undefined) return rows
  return rows.filter((row) => (row as { sessionId?: unknown }).sessionId === sessionId)
}

function include(target: Record<string, unknown>, key: string, value: unknown): void {
  if (value !== undefined && value !== null) target[key] = value
}

function msg(e: unknown): string {
  return e && typeof e === 'object' && 'message' in e ? String((e as { message: unknown }).message) : String(e)
}

/** Concatenate the text blocks of a message content array (tool/result + user/message share this shape). */
function textOfContent(content: unknown): string {
  if (!Array.isArray(content)) return ''
  const parts: string[] = []
  for (const block of content) {
    if (block && typeof block === 'object' && (block as { type?: unknown }).type === 'text' && typeof (block as { text?: unknown }).text === 'string') {
      parts.push((block as { text: string }).text)
    }
  }
  return parts.join('\n')
}

/** Bound a detail string so the review payload stays small. */
function cap(text: string, max: number, lang: 'zh' | 'en' = 'en'): string {
  if (text.length <= max) return text
  return `${text.slice(0, max)}\u2026${lang === 'zh' ? '（已截断）' : ' (truncated)'}`
}

/** Pretty-print the raw model arguments JSON; fall back to the raw string when unparseable. */
function prettyArgs(raw: unknown): string {
  if (typeof raw !== 'string') return String(raw === undefined || raw === null ? '' : raw)
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
}

/**
 * Validate a policy-table payload (mirror of the old vm-side validator).
 * The returned problem string is displayed verbatim in the panel's config
 * status area, so it localizes by the panel language (`lang`, default `en`).
 */
export function validateTable(t: unknown, lang: 'zh' | 'en' = 'en'): string | null {
  const ve = (zh: string, en: string): string => (lang === 'zh' ? zh : en)
  if (!t || typeof t !== 'object' || Array.isArray(t)) return ve('策略表格式不正确（必须是对象）', 'Invalid policy table format (must be an object)')
  const table = t as { v?: unknown; policies?: unknown }
  if (table.v !== 1) return ve('策略表版本 v 必须为 1', 'Policy table version v must be 1')
  if (!Array.isArray(table.policies)) return ve('policies 必须是数组', 'policies must be an array')
  const OPERATORS = ['eq', 'neq', 'contains', 'in', 'matches', 'regex']
  const ACTIONS = ['allow', 'block', 'ask', 'warn']
  // Accept every native policy hook plus the legacy v0.1.x names; canonicalize
  // on save so the table on disk is always native.
  const HOOKS = [...POLICY_HOOKS, 'before_tool_call', 'tool_result_persist', 'after_tool_call', 'before_prompt_build']
  for (const p of table.policies as Array<Record<string, unknown>>) {
    if (!p || typeof p !== 'object' || typeof p.id !== 'string' || p.id.length === 0) return ve('每个策略都需要非空的 id', 'Each policy requires a non-empty id')
    // Single-hook contract: a policy must bind exactly one known hook (no `*`
    // all, no multi-select). ask only works on tools/pre-execute, the only
    // hook with an approval seam, so ask policies are pinned to it.
    if (p.hooks !== undefined) {
      if (!Array.isArray(p.hooks) || p.hooks.length !== 1 || typeof p.hooks[0] !== 'string' || HOOKS.indexOf(p.hooks[0]) === -1) {
        return ve(
          `策略 ${p.id} 必须绑定且只绑定一个钩子（已知原生 seam：tools/pre-execute | tools/post-execute | tools/result | agent/pre-step | agent/turn-stopping | agent/session-start | subagent/start | subagent/end | tools/guard）`,
          `Policy ${p.id} must bind exactly one hook (a known native seam: tools/pre-execute | tools/post-execute | tools/result | agent/pre-step | agent/turn-stopping | agent/session-start | subagent/start | subagent/end | tools/guard)`,
        )
      }
      if (p.action === 'ask' && canonicalHook(p.hooks[0]) !== 'tools/pre-execute') {
        return ve(`策略 ${p.id}：ask 仅支持 tools/pre-execute（唯一有审批通道的钩子）`, `Policy ${p.id}: ask only works on tools/pre-execute (the only hook with an approval seam)`)
      }
      p.hooks = [canonicalHook(p.hooks[0])]
    }
    if (!Array.isArray(p.rules) || p.rules.length === 0) return ve(`策略 ${p.id} 至少需要一条规则`, `Policy ${p.id} requires at least one rule`)
    for (const r of p.rules as Array<Record<string, unknown>>) {
      if (!r || typeof r !== 'object') return ve(`策略 ${p.id} 存在非法规则`, `Policy ${p.id} has an invalid rule`)
      if (typeof r.field !== 'string' || r.field.length === 0) return ve(`策略 ${p.id} 的规则缺少 field`, `A rule of policy ${p.id} is missing field`)
      if (OPERATORS.indexOf(r.operator as string) === -1) return ve(`策略 ${p.id} 使用了未知操作符 ${String(r.operator)}`, `Policy ${p.id} uses an unknown operator ${String(r.operator)}`)
      if (r.operator === 'in' && !Array.isArray(r.value)) return ve(`策略 ${p.id} 的 in 规则要求 value 为数组`, `The in rule of policy ${p.id} requires value to be an array`)
    }
    if (ACTIONS.indexOf(p.action as string) === -1) return ve(`策略 ${p.id} 使用了未知动作 ${String(p.action)}`, `Policy ${p.id} uses an unknown action ${String(p.action)}`)
  }
  return null
}

/** Per-session correlation context folded from live session events. */
interface SessionContext {
  calls: Map<string, { name?: unknown; arguments?: unknown; turn?: unknown; step?: unknown }>
  results: Map<string, string>
  stepPrompts: Map<string, string>
  approvalByCallId: Map<string, string>
}

/** Build the call/result/prompt/approval correlation maps of one session's event log. */
function buildSessionContext(events: readonly unknown[]): SessionContext {
  const calls = new Map<string, { name?: unknown; arguments?: unknown; turn?: unknown; step?: unknown }>()
  const results = new Map<string, string>()
  const stepPrompts = new Map<string, string>()
  // Harness approval trail: `approval/asked` pairs a request id with the tool
  // call it asks about, and the always-following `approval/decided` closes it
  // with the outcome. Guard ask verdicts share the same tool callId, so the
  // resolved outcome attaches to the verdict row below.
  const approvalCallIds = new Map<string, string>()
  const approvalByCallId = new Map<string, string>()
  let curTurn: unknown
  let curStep: unknown
  for (const raw of events) {
    const ev = raw as { type?: unknown; data?: unknown; seq?: unknown; time?: unknown }
    const data = ev.data as Record<string, unknown> | null | undefined
    if (!data || typeof data !== 'object') continue
    if (ev.type === 'turn/start') {
      curTurn = data.turn
      curStep = undefined
    } else if (ev.type === 'step/start') {
      curStep = data.step
    } else if (ev.type === 'tool/call' && data.callId !== undefined) {
      calls.set(String(data.callId), { name: data.name, arguments: data.arguments, turn: data.turn, step: data.step })
    } else if (ev.type === 'tool/result') {
      const source = (data.message as { source?: { callId?: unknown } | undefined } | undefined)?.source
      const callId = source?.callId
      if (callId !== undefined) {
        results.set(String(callId), textOfContent((data.message as { content?: unknown } | undefined)?.content))
      }
    } else if (ev.type === 'approval/asked' && data.id !== undefined && data.callId !== undefined) {
      approvalCallIds.set(String(data.id), String(data.callId))
    } else if (ev.type === 'approval/decided' && data.id !== undefined && data.outcome !== undefined) {
      const callId = approvalCallIds.get(String(data.id))
      if (callId !== undefined) approvalByCallId.set(callId, String(data.outcome))
    } else if (ev.type === 'user/message' && curTurn !== undefined && curStep !== undefined) {
      const key = `${String(curTurn)}:${String(curStep)}`
      const text = textOfContent(data.content)
      if (text) stepPrompts.set(key, (stepPrompts.has(key) ? stepPrompts.get(key) + '\n\n' : '') + text)
    }
  }
  return { calls, results, stepPrompts, approvalByCallId }
}

/** Attach  the durable per-row correlation detail (never persisted). The
 * truncation marker of bounded previews localizes by `lang`. */
function attachDetail(item: Record<string, unknown>, ctx: SessionContext, row: StoredVerdict, lang: 'zh' | 'en'): void {
  if (row.callId !== undefined) {
    const approvalOutcome = ctx.approvalByCallId.get(String(row.callId))
    if (approvalOutcome !== undefined) item.approval = approvalOutcome
    const call = ctx.calls.get(String(row.callId))
    if (call !== undefined) {
      const detail: Record<string, unknown> = { kind: 'tool', turn: call.turn, step: call.step, arguments: cap(prettyArgs(call.arguments), DETAIL_CAP, lang) }
      const result = ctx.results.get(String(row.callId))
      if (result) detail.result = cap(result, DETAIL_CAP, lang)
      item.detail = detail
    }
    return
  }
  if (row.hook === 'agent/pre-step') {
    // Prefer the content persisted at record time (the assembled user messages
    // the guard actually inspected), so it never misses on continuation or
    // boundary steps. Fall back to the turn/step user-message correlation only
    // for records that predate that field.
    const stored = typeof row.content === 'string' && row.content !== '' ? row.content : ''
    const correlated = row.turn !== undefined && row.step !== undefined
      ? (ctx.stepPrompts.get(`${String(row.turn)}:${String(row.step)}`) ?? '')
      : ''
    const content = stored || correlated
    if (content) item.detail = { kind: 'prompt', content: cap(content, DETAIL_CAP, lang) }
  }
}

/**
 * Fold the guard's verdict trail out of the plugin's audit file, correlating
 * each stored row with its live-session durable context (tool/call raw
 * arguments, tool/result text, per-step user prompts) and with the harness
 * approval outcome (`approval/asked` + `approval/decided`) for ask verdicts.
 * Purely additive and read-only; stored records themselves stay compact, and
 * verdicts record at or before the panel's dismissal cutoff are hidden from
 * the review view. Context detail is bounded (~4 000 chars/row).
 */
export function foldVerdicts(
  agents: { list(): Array<{ id: unknown; session: { events: readonly unknown[] } }> },
  verdictClearTime: number,
  storedRows: readonly StoredVerdict[],
  lang: 'zh' | 'en' = 'en',
): unknown[] {
  const bySession = new Map<string, SessionContext>()
  for (const agent of agents.list()) {
    bySession.set(String(agent.id), buildSessionContext(agent.session.events))
  }
  const out: Array<Record<string, unknown>> = []
  for (const rawRow of storedRows) {
    // Rows may arrive from older hosts / raw in-memory rows with legacy hook
    // names; canonicalize once so every folded consumer sees native seams.
    const row: StoredVerdict = { ...rawRow, hook: canonicalHook(rawRow.hook) }
    if (row.time <= verdictClearTime) continue
    const item: Record<string, unknown> = {
      sessionId: row.sessionId,
      seq: row.seq,
      time: row.time,
    }
    include(item, 'hook', row.hook)
    include(item, 'action', row.action)
    include(item, 'outcome', row.outcome)
    include(item, 'turn', row.turn)
    include(item, 'step', row.step)
    include(item, 'tool', row.tool)
    include(item, 'callId', row.callId)
    include(item, 'policyId', row.policyId)
    include(item, 'message', row.message)
    include(item, 'noApprovalSeam', row.noApprovalSeam === true ? true : undefined)
    include(item, 'content', row.content === undefined ? undefined : row.content)
    include(item, 'kind', row.kind)
    include(item, 'modelStatus', row.modelStatus)
    include(item, 'note', row.note)
    include(item, 'modelLate', row.modelLate === true ? true : undefined)
    include(item, 'provider', row.provider)
    include(item, 'request', row.request)
    include(item, 'response', row.response)
    include(item, 'durationMs', row.durationMs)
    include(item, 'error', row.error)
    const ctx = bySession.get(row.sessionId)
    if (ctx !== undefined) attachDetail(item, ctx, row, lang)
    out.push(item)
  }
  out.sort((a, b) => (Number(b.time) || 0) - (Number(a.time) || 0))
  return out
}

/**
 * Register the panel routes on the webServer service. Registration is
 * idempotent per (kind, path); a duplicate throws, which the caller surfaces.
 *
 * The `agents` service is resolved lazily from the context at call time so
 * the routes stay registered even in assemblies where the agent registry is
 * absent (headless). Those requests answer `{ ok:false }` gracefully.
 *
 * @returns a disposer unregistering all routes, or `null` when the webServer
 * service is not (yet) available (caller may retry via `internal/service`), or
 * when the webServer binds a non-loopback host without a `webRuntime` trusted
 * allowlist (the routes are deliberately not exposed on the network. See
 * module docs).
 */
export function registerGuardApi(ctx: Context, deps: GuardApiDeps): (() => void) | null {
  const webServer = ctx.get('webServer') as GuardWebServer | undefined
  if (webServer === undefined) {
    ctx.logger.debug(`${PREFIX} webServer unavailable (yet); guard panel API not registered`)
    return null
  }
  // A non-loopback binding would expose session plaintext + control routes to
  // the network. Refuse unless the DSH Web runtime has paired an explicit
  // `trustedHosts` allowlist (bind-derived LAN literals or `--trusted-host`),
  // which the per-request authorize() fence then enforces. When the webRuntime
  // service has not been provided yet (it mounts after webServer), a missing
  // allowlist makes this return null and index.ts retries on the webRuntime
  // service event — no panel until the allowlist is actually available.
  const trusted = trustedHostsOf(ctx)
  if (webServer.host !== undefined && webServer.host !== '127.0.0.1' && trusted.length === 0) {
    ctx.logger.warn(`${PREFIX} webServer binds ${webServer.host} with no webRuntime.trustedHosts allowlist; `
      + 'the guard panel API is NOT registered. Pass `dsh web --trusted-host` authorities, '
      + 'or accept loopback-only panel access.')
    return null
  }

  /** Verdict dismissal cutoff (ms): the "Clear log" action sets it to now. */
  let verdictClearTime = 0
  /** Per-process unpredictable CSRF token, issued to the page as a SameSite=Strict cookie. */
  const csrfToken = randomBytes(32).toString('base64url')

  const csrfCookie = `${CSRF_COOKIE}=${csrfToken}; Path=/; SameSite=Strict; HttpOnly`

  /** Panel language resolved by the caller (reported DSH locale > persisted preference). */
  const lang = (): 'zh' | 'en' => deps.lang !== undefined
    ? deps.lang()
    : (deps.getPrefs().locale === 'zh' ? 'zh' : 'en')

  /** Localize a fixed user-visible message by the current panel language. */
  function localized(zh: string, en: string): string {
    return lang() === 'zh' ? zh : en
  }

  /**
   * Validate a `modelReview` settings patch from the panel. Accepts a partial
   * object (fields present are validated, absent ones stay untouched by the
   * caller's merge); returns the validated fields or `null` when any present
   * field is invalid (fail-loud).
   */
  function validateModelReviewPatch(
    candidate: unknown,
  ): Partial<ModelReviewPrefs> | null {
    if (candidate === null || typeof candidate !== 'object' || Array.isArray(candidate)) return null
    const record = candidate as Record<string, unknown>
    const out: Partial<ModelReviewPrefs> = {}
    if (Object.prototype.hasOwnProperty.call(record, 'enabled')) {
      if (typeof record.enabled !== 'boolean') return null
      out.enabled = record.enabled
    }
    if (Object.prototype.hasOwnProperty.call(record, 'protocol')) {
      // Wire protocol for the dedicated review endpoint (custom mode only).
      if (record.protocol !== 'openai-chat' && record.protocol !== 'openai-responses' && record.protocol !== 'anthropic') return null
      out.protocol = record.protocol
    }
    if (Object.prototype.hasOwnProperty.call(record, 'thinking')) {
      // Dedicated-review reasoning setting; only meaningful in custom mode,
      // but accepted in any mode so switching mode never drops the preference.
      // Legacy boolean archives keep working: true → 'medium', false → 'default'.
      const value = record.thinking
      if (value === true) out.thinking = 'medium'
      else if (value === false) out.thinking = 'default'
      else if (value === 'default' || value === 'off' || value === 'low' || value === 'medium' || value === 'high') out.thinking = value
      else return null
    }
    if (Object.prototype.hasOwnProperty.call(record, 'mode')) {
      if (record.mode !== 'session' && record.mode !== 'custom') return null
      out.mode = record.mode
    }
    if (Object.prototype.hasOwnProperty.call(record, 'makeupReview')) {
      // Post-hoc make-up review switch (session mode only; off by default).
      if (typeof record.makeupReview !== 'boolean') return null
      out.makeupReview = record.makeupReview
    }
    if (Object.prototype.hasOwnProperty.call(record, 'baselineTemplates')) {
      // Built-in baseline templates (the three shipped audit prompts). The
      // cards are READ-ONLY: id / name / hooks / prompt always come from
      // BASELINE_REVIEW_TEMPLATES, so the panel can only flip each card's
      // `enabled` switch. Any id outside the shipped triple (or a duplicate) is
      // rejected; the result is normalized back to shipped order so the
      // execution order stays the baseline order regardless of send order.
      const list = record.baselineTemplates
      if (!Array.isArray(list) || list.length > BASELINE_REVIEW_TEMPLATES.length) return null
      const shipped = new Map<string, ReviewPromptTemplate>(BASELINE_REVIEW_TEMPLATES.map((b) => [b.id, { ...b }]))
      const seen = new Set<string>()
      const updates = new Map<string, boolean>()
      for (const item of list) {
        if (item === null || typeof item !== 'object' || Array.isArray(item)) return null
        const entry = item as Record<string, unknown>
        if (typeof entry.id !== 'string') return null
        const id = entry.id.trim()
        if (!shipped.has(id) || seen.has(id)) return null
        const enabled = entry.enabled === undefined ? shipped.get(id)!.enabled : entry.enabled
        if (typeof enabled !== 'boolean') return null
        seen.add(id)
        updates.set(id, enabled)
      }
      out.baselineTemplates = BASELINE_REVIEW_TEMPLATES.map((base) => ({
        ...base,
        ...(updates.has(base.id) ? { enabled: updates.get(base.id)! } : {}),
      }))
    }
    if (Object.prototype.hasOwnProperty.call(record, 'templates')) {
      // Custom review templates: each binds one or more hooks (multi-select);
      // within each hook the array order is the priority. The panel always
      // sends the full list, so the caller's merge replaces it wholesale.
      // Legacy v0.1.x archives carry a single `hook` string instead of the
      // `hooks` array — accepted and normalized to the array form.
      const templates = record.templates
      if (!Array.isArray(templates) || templates.length > MAX_REVIEW_TEMPLATES) return null
      const outTemplates: ReviewPromptTemplate[] = []
      for (const item of templates) {
        if (item === null || typeof item !== 'object' || Array.isArray(item)) return null
        const entry = item as Record<string, unknown>
        if (typeof entry.id !== 'string' || entry.id.trim().length === 0) return null
        // Accept `hooks` (array) or the deprecated single `hook`; at least
        // one must be a well-formed binding. Every value canonicalizes and
        // must land on a known native seam; duplicates collapse.
        if (entry.hooks !== undefined && !Array.isArray(entry.hooks)) return null
        const rawHooks = Array.isArray(entry.hooks)
          ? entry.hooks
          : entry.hook !== undefined ? [entry.hook] : undefined
        if (rawHooks === undefined) return null
        const hookSet: ReviewTemplateHook[] = []
        for (const h of rawHooks) {
          if (typeof h !== 'string') return null
          const canonical = canonicalHook(h) as ReviewTemplateHook
          if (!(HOOK_OPTIONS as readonly string[]).includes(canonical)) return null
          if (!hookSet.includes(canonical)) hookSet.push(canonical)
        }
        if (typeof entry.name !== 'string' || typeof entry.prompt !== 'string') return null
        const enabled = entry.enabled === undefined ? true : entry.enabled
        if (typeof enabled !== 'boolean') return null
        // Disposition cap (optional): absent = uncapped; present it must be
        // one of the four guard actions. Anything else rejects the patch.
        let action: ReviewPromptTemplate['action'] | undefined
        if (entry.action !== undefined) {
          if (typeof entry.action !== 'string' || !(TEMPLATE_ACTIONS as readonly string[]).includes(entry.action)) return null
          action = entry.action as ReviewPromptTemplate['action']
        }
        outTemplates.push({
          id: entry.id.trim(),
          name: entry.name,
          hooks: hookSet,
          enabled,
          prompt: entry.prompt,
          ...(action !== undefined ? { action } : {}),
        })
      }
      out.templates = outTemplates
    }
    for (const key of ['baseUrl', 'apiKey', 'model'] as const) {
      if (Object.prototype.hasOwnProperty.call(record, key)) {
        const value = record[key]
        if (typeof value !== 'string') return null
        out[key] = value
      }
    }
    if (Object.prototype.hasOwnProperty.call(record, 'timeoutMs')) {
      if (typeof record.timeoutMs !== 'number' || !Number.isFinite(record.timeoutMs) || record.timeoutMs <= 0 || record.timeoutMs > 60_000) {
        return null
      }
      out.timeoutMs = record.timeoutMs
    }
    return out
  }

  function sendJson(res: ServerResponse, status: number, body: unknown): void {
    const payload = JSON.stringify(body)
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'set-cookie': csrfCookie,
    })
    res.end(payload)
  }

  /** Write the failure envelope (500 for any non-`GuardApiError`). */
  function writeError(res: ServerResponse, error: unknown): void {
    const message = error instanceof Error ? error.message : String(error)
    sendJson(res, 500, { ok: false, error: { code: 'internal', message } })
  }

  /** Read and parse the JSON request body (bounded; empty → `{}`). */
  async function readJsonBody(req: IncomingMessage): Promise<unknown> {
    const chunks: Buffer[] = []
    let total = 0
    for await (const chunk of req) {
      const buffer = Buffer.from(chunk)
      total += buffer.length
      if (total > MAX_BODY_BYTES) {
        throw new Error('request body too large')
      }
      chunks.push(buffer)
    }
    const text = Buffer.concat(chunks).toString('utf8')
    if (text.trim() === '') return {}
    try {
      return JSON.parse(text) as unknown
    } catch {
      throw new Error('request body is not valid JSON')
    }
  }

  const forbidden = { ok: false, error: { code: 'forbidden', message: 'forbidden' } }

  /** Base access control: loopback-or-allowlist Host + no cross-site browser fetch + same-origin Origin. */
  function authorize(req: IncomingMessage, res: ServerResponse): boolean {
    const trusted = trustedHostsOf(ctx)
    if (!isLoopback(req) && !matchesTrustedHost(req.headers.host, trusted)) {
      sendJson(res, 403, forbidden)
      return false
    }
    const secFetchSite = req.headers['sec-fetch-site']
    if (typeof secFetchSite === 'string' && secFetchSite.toLowerCase() === 'cross-site') {
      sendJson(res, 403, forbidden)
      return false
    }
    const origin = req.headers.origin
    if (typeof origin === 'string' && origin.trim() !== '') {
      let originHost: string
      let originAuthority: string | undefined
      try {
        const u = new URL(origin)
        originHost = u.hostname.toLowerCase()
        // Port equality is enforced only when the request Host carries an
        // explicit port (`localhost:3080`); a bare curl-style `Host: localhost`
        // falls back to a hostname-only comparison so it cannot cross ports but
        // does not break hostless pipelines (N10/B2).
        originAuthority = u.port === '' ? undefined : `${originHost}:${u.port}`
      } catch {
        sendJson(res, 403, forbidden)
        return false
      }
      const reqAuthority = authorityOfHost(req.headers.host)
      const isLoopbackOrigin = isLoopbackName(originHost)
      const isTrustedOrigin = !isLoopbackOrigin && isTrustedHostname(originHost, trusted)
      if ((!isLoopbackOrigin && !isTrustedOrigin) || originHost !== hostnameOfHost(req.headers.host)
        || (reqAuthority !== undefined && originAuthority !== reqAuthority)) {
        sendJson(res, 403, forbidden)
        return false
      }
    }
    return true
  }

  /** Access control for mutating requests: authorize + explicit JSON bodies + CSRF cookie. */
  function authorizeMutation(req: IncomingMessage, res: ServerResponse): boolean {
    if (!authorize(req, res)) return false
    if (expectsBody(req) && !isJsonContentType(req)) {
      sendJson(res, 415, { ok: false, error: { code: 'media-type-error', message: 'content-type must be application/json' } })
      return false
    }
    const cookieHeader = req.headers.cookie
    const hasToken = typeof cookieHeader === 'string'
      && cookieHeader.split(';').some((part) => {
        const eq = part.indexOf('=')
        if (eq === -1) return false
        const key = part.slice(0, eq).trim()
        return key === CSRF_COOKIE && part.slice(eq + 1).trim() === csrfToken
      })
    if (!hasToken) {
      sendJson(res, 403, forbidden)
      return false
    }
    return true
  }

  const routes: GuardWebRoute[] = [
    {
      kind: 'exact',
      path: '/guard/api/verdicts',
      handler: async (req, res): Promise<void> => {
        if (!authorize(req, res)) return
        if (req.method !== 'GET') {
          sendJson(res, 405, { ok: false, error: { code: 'method-error', message: 'method not allowed' } })
          return
        }
        try {
          const agents = ctx.get('agents') as { list(): Array<{ id: unknown; session: { events: readonly unknown[] } }> } | undefined
          if (!agents) {
            sendJson(res, 200, [])
            return
          }
          const rows = readVerdictLog(deps.paths.verdictLogPath)
          const after = Number(queryParam(req, 'after') ?? 0)
          const visible = Number.isFinite(after) && after > 0 ? rows.filter((r) => r.seq > after) : rows
          sendJson(res, 200, filterVerdicts(foldVerdicts(agents, verdictClearTime, visible, lang()), queryParam(req, 'sessionId')))
        } catch (error) {
          writeError(res, error)
        }
      },
    },
    {
      kind: 'exact',
      path: '/guard/api/clear-verdicts',
      handler: async (req, res): Promise<void> => {
        if (!authorizeMutation(req, res)) return
        if (req.method !== 'POST') {
          sendJson(res, 405, { ok: false, error: { code: 'method-error', message: 'method not allowed' } })
          return
        }
        try {
          const before = readVerdictLog(deps.paths.verdictLogPath).length
          clearVerdictLog(deps.paths.verdictLogPath)
          verdictClearTime = Date.now()
          sendJson(res, 200, { ok: true, message: localized(
            `已从审查日志中清除 ${before} 条判决`,
            `Cleared ${before} verdict(s) from the review log`,
          ) })
        } catch (error) {
          writeError(res, error)
        }
      },
    },
    {
      kind: 'exact',
      path: '/guard/api/policies',
      handler: async (req, res): Promise<void> => {
        if (!authorize(req, res)) return
        if (req.method === 'GET') {
          try {
            const raw = readFileSync(deps.paths.effectivePath, 'utf8')
            sendJson(res, 200, { ok: true, data: JSON.parse(raw) })
          } catch (error) {
            sendJson(res, 200, { ok: false, error: localized('读取当前生效配置失败：', 'Failed to read the currently effective configuration: ') + msg(error) })
          }
          return
        }
        if (req.method === 'POST') {
          if (!authorizeMutation(req, res)) return
          try {
            const payload = await readJsonBody(req)
            const problem = validateTable(payload, lang())
            if (problem) {
              sendJson(res, 200, { ok: false, error: problem })
              return
            }
            deps.writeUiPolicies(`${JSON.stringify(payload, null, 2)}\n`)
            sendJson(res, 200, { ok: true, message: localized(
              '已保存。守护引擎将在约 1 秒内自动重新加载。',
              'Saved. The guard engine will automatically reload it within ~1 second.',
            ) })
          } catch (error) {
            writeError(res, error)
          }
          return
        }
        sendJson(res, 405, { ok: false, error: { code: 'method-error', message: 'method not allowed' } })
      },
    },
    {
      kind: 'exact',
      path: '/guard/api/reset-policies',
      handler: async (req, res): Promise<void> => {
        if (!authorizeMutation(req, res)) return
        if (req.method !== 'POST') {
          sendJson(res, 405, { ok: false, error: { code: 'method-error', message: 'method not allowed' } })
          return
        }
        try {
          deps.writeUiPolicies(`${JSON.stringify({ v: 1, reset: true }, null, 2)}\n`)
          sendJson(res, 200, { ok: true, message: localized(
            '已恢复 cordis.yml 基线；约 1 秒内生效。',
            'Restored the cordis.yml baseline; effective within ~1 second.',
          ) })
        } catch (error) {
          writeError(res, error)
        }
      },
    },
    {
      kind: 'exact',
      path: '/guard/api/lang',
      handler: async (req, res): Promise<void> => {
        if (!authorize(req, res)) return
        if (req.method === 'GET') {
          try {
            const prefs = deps.getPrefs()
            sendJson(res, 200, { locale: prefs.locale })
          } catch (error) {
            writeError(res, error)
          }
          return
        }
        if (req.method === 'POST') {
          if (!authorizeMutation(req, res)) return
          try {
            const payload = await readJsonBody(req)
            const locale = (payload as { locale?: unknown }).locale
            if (locale !== 'auto' && locale !== 'zh' && locale !== 'en') {
              sendJson(res, 200, { ok: false, error: localized('locale 必须是 auto | zh | en 之一', 'locale must be one of auto | zh | en') })
              return
            }
            await deps.updatePrefs({ locale })
            sendJson(res, 200, { ok: true, message: 'saved', locale })
          } catch (error) {
            writeError(res, error)
          }
          return
        }
        sendJson(res, 405, { ok: false, error: { code: 'method-error', message: 'method not allowed' } })
      },
    },
    {
      kind: 'exact',
      path: '/guard/api/lang/resolved',
      handler: async (req, res): Promise<void> => {
        if (req.method !== 'POST') {
          sendJson(res, 405, { ok: false, error: { code: 'method-error', message: 'method not allowed' } })
          return
        }
        if (!authorizeMutation(req, res)) return
        try {
          const payload = await readJsonBody(req)
          const locale = (payload as { locale?: unknown }).locale
          if (locale !== 'zh' && locale !== 'en') {
            sendJson(res, 200, { ok: false, error: localized('locale 必须是 zh | en 之一', 'locale must be one of zh | en') })
            return
          }
          deps.reportResolvedLocale(locale)
          sendJson(res, 200, { ok: true })
        } catch (error) {
          writeError(res, error)
        }
      },
    },
    {
      kind: 'exact',
      path: '/guard/api/prefs',
      handler: async (req, res): Promise<void> => {
        if (!authorize(req, res)) return
        if (req.method === 'GET') {
          try {
            sendJson(res, 200, deps.getPrefs())
          } catch (error) {
            writeError(res, error)
          }
          return
        }
        if (req.method === 'POST') {
          if (!authorizeMutation(req, res)) return
          try {
            const payload = await readJsonBody(req)
            const patch: Partial<GuardPrefs> = {}
            if (Object.prototype.hasOwnProperty.call(payload, 'locale')) {
              const locale = (payload as { locale?: unknown }).locale
              if (locale !== 'auto' && locale !== 'zh' && locale !== 'en') {
                sendJson(res, 200, { ok: false, error: localized('locale 必须是 auto | zh | en 之一', 'locale must be one of auto | zh | en') })
                return
              }
              patch.locale = locale
            }
            if (Object.prototype.hasOwnProperty.call(payload, 'showSessionTab')) {
              const flag = (payload as { showSessionTab?: unknown }).showSessionTab
              if (typeof flag !== 'boolean') {
                sendJson(res, 200, { ok: false, error: localized('showSessionTab 必须为布尔值', 'showSessionTab must be a boolean') })
                return
              }
              patch.showSessionTab = flag
            }
            if (Object.prototype.hasOwnProperty.call(payload, 'showHeaderButton')) {
              const flag = (payload as { showHeaderButton?: unknown }).showHeaderButton
              if (typeof flag !== 'boolean') {
                sendJson(res, 200, { ok: false, error: localized('showHeaderButton 必须为布尔值', 'showHeaderButton must be a boolean') })
                return
              }
              patch.showHeaderButton = flag
            }
            if (Object.prototype.hasOwnProperty.call(payload, 'guardEnabled')) {
              const flag = (payload as { guardEnabled?: unknown }).guardEnabled
              if (typeof flag !== 'boolean') {
                sendJson(res, 200, { ok: false, error: localized('guardEnabled 必须为布尔值', 'guardEnabled must be a boolean') })
                return
              }
              patch.guardEnabled = flag
            }
            if (Object.prototype.hasOwnProperty.call(payload, 'recordAllow')) {
              const flag = (payload as { recordAllow?: unknown }).recordAllow
              if (typeof flag !== 'boolean') {
                sendJson(res, 200, { ok: false, error: localized('recordAllow 必须为布尔值', 'recordAllow must be a boolean') })
                return
              }
              patch.recordAllow = flag
            }
            if (Object.prototype.hasOwnProperty.call(payload, 'rulesEnabled')) {
              const flag = (payload as { rulesEnabled?: unknown }).rulesEnabled
              if (typeof flag !== 'boolean') {
                sendJson(res, 200, { ok: false, error: localized('rulesEnabled 必须为布尔值', 'rulesEnabled must be a boolean') })
                return
              }
              patch.rulesEnabled = flag
            }
            if (Object.prototype.hasOwnProperty.call(payload, 'modelReview')) {
              const validated = validateModelReviewPatch((payload as { modelReview?: unknown }).modelReview)
              if (validated === null) {
                sendJson(res, 200, { ok: false, error: localized('modelReview 配置不合法', 'modelReview config is invalid') })
                return
              }
              // Shallow-merge onto the live prefs so a partial patch (one field
              // changed in the panel) never drops the other model-review fields.
              const current = deps.getPrefs().modelReview ?? {}
              patch.modelReview = {
                ...(current ?? {}),
                ...validated,
              }
            }
            if (Object.keys(patch).length > 0) await deps.updatePrefs(patch)
            sendJson(res, 200, { ok: true, message: 'saved', ...deps.getPrefs() })
          } catch (error) {
            writeError(res, error)
          }
          return
        }
        sendJson(res, 405, { ok: false, error: { code: 'method-error', message: 'method not allowed' } })
      },
    },
  ]

  const disposers: Array<() => void> = []
  for (const route of routes) {
    disposers.push(webServer.register(route))
  }
  ctx.logger.info(`${PREFIX} guard panel API registered: ${routes.length} routes under /guard/api`)
  return () => {
    for (const dispose of disposers) dispose()
  }
}