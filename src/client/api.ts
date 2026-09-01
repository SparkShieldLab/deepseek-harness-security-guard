/**
 * Typed fetch wrapper over the /guard JSON API.
 *
 * The host half (guard-api.ts) registers 6 routes on the webServer; the
 * panel talks to them with plain `fetch`. The wire protocol is identical to
 * the old dynamic-plugin `harness.handle` handlers, so the client semantics
 * did not change, only the transport.
 *
 * Route summary (see guard-api.ts for the exact envelope shapes):
 *
 *   GET  /guard/api/verdicts        → GuardVerdictRow[] (optional ?sessionId= narrows to one session)
 *   POST /guard/api/clear-verdicts  → { ok: true, message }
 *   GET  /guard/api/policies        → { ok: true, data } | { ok: false, error }
 *   POST /guard/api/policies        → { ok: true, message } | { ok: false, error }
 *   POST /guard/api/reset-policies  → { ok: true, message } | { ok: false, error }
 *   GET  /guard/api/lang            → { locale: GuardLocale }
 *   POST /guard/api/lang            → { ok: true, message, locale } | { ok: false, error }
 *   POST /guard/api/lang/resolved   → { ok: true } | { ok: false, error } ({ locale: 'zh' | 'en' })
 *   GET  /guard/api/prefs           → { locale, showSessionTab, showHeaderButton, guardEnabled }
 *   POST /guard/api/prefs           → { ok: true, message, locale, showSessionTab, showHeaderButton, guardEnabled } | { ok: false, error }
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/client/api
 */

/** One verdict row (folded by the host from every live session's [dsh-guard] records). */
export interface GuardVerdictRow {
  sessionId: string
  seq: number
  time: number
  hook?: string
  action?: string
  outcome?: string
  turn?: number
  step?: number
  tool?: string
  callId?: string
  policyId?: string
  message?: string
  /** Which review stage produced the final action: `rule` / `model` / `both`. */
  source?: string
  /** The model stage's verdict, when the model stage ran. */
  modelVerdict?: { action: string; reason: string; confidence?: number }
  /**
   * Audit-row kind. Absent (or `'rule'`) = a merged rule-verdict row;
   * `'model'` = a dedicated model-review attempt row.
   */
  kind?: 'rule' | 'model'
  /** Model-review attempt status (`'ok'` / `'error'` / `'skipped'`), `kind: 'model'` rows only. */
  modelStatus?: string
  /** Which model served the review request, `kind: 'model'` rows only. */
  provider?: { mode: 'session' | 'custom'; provider?: string; model?: string; baseUrl?: string }
  /** The rendered review prompt (request body), `kind: 'model'` rows only. */
  request?: string
  /** The model's raw output (response body), `kind: 'model'` rows only. */
  response?: string
  /** Wall-clock duration of the model call (ms), `kind: 'model'` rows only. */
  durationMs?: number
  /** Failure detail for a failed model-review attempt (`modelStatus: 'error'`). */
  error?: string
  /** Skip reason / make-up annotation (`modelStatus: 'skipped'` or `modelLate`). */
  note?: string
  /** True when this row is a post-hoc make-up review (audit-only, non-enforcing). */
  modelLate?: boolean
  /** True when an `ask` verdict ran on a hook without an approval seam and was
   * degraded to a reject/block instead of waiting on the human. The panel
   * labels such rows so "Awaiting confirmation" is never mistaken for a pending prompt. */
  noApprovalSeam?: boolean
  /** The harness approval outcome for a call the guard asked about (ask verdicts). */
  approval?: string
  detail?: { kind: 'tool'; turn?: number; step?: number; arguments?: string; result?: string }
    | { kind: 'prompt'; content: string }
}

/** The currently-effective table served by GET /guard/api/policies. */
export interface GuardEffectiveTable {
  v: number
  source: string
  version: number
  updated: number
  policies: Array<Record<string, unknown>>
  error?: string
}

/** Success/failure envelope of the mutation routes. */
export interface GuardActionResult {
  ok: boolean
  message?: string
  error?: string
}

/** GET /guard/api/policies envelope. */
export interface GuardPoliciesResult {
  ok: boolean
  data?: GuardEffectiveTable
  error?: string
}

/** Panel language preference ('auto' follows the DSH active locale). */
export type GuardLocale = 'auto' | 'zh' | 'en'

/** GET /guard/api/lang response. */
export interface GuardLangResult {
  locale: GuardLocale
  ok?: boolean
  message?: string
  error?: string
}

/**
 * The guard hooks a review template / baseline scope can bind to — every
 * NATIVE deepseek-harness seam (the same surface the rule table uses). Legacy
 * v0.1.x plugin-internal names are canonicalized by {@link canonicalGuardHook}.
 */
export type TheGuardHook =
  | 'tools/pre-execute'
  | 'tools/post-execute'
  | 'tools/result'
  | 'agent/pre-step'
  | 'agent/turn-stopping'
  | 'agent/session-start'
  | 'subagent/start'
  | 'subagent/end'
  | 'tools/guard'

/** Legacy v0.1.x plugin-internal hook names → their native seams. */
const LEGACY_HOOK_ALIASES: Readonly<Record<string, TheGuardHook>> = {
  before_tool_call: 'tools/pre-execute',
  tool_result_persist: 'tools/post-execute',
  after_tool_call: 'tools/result',
  before_prompt_build: 'agent/pre-step',
}

/** Canonicalize a hook name (legacy plugin-internal → native seam; identity otherwise). */
export function canonicalGuardHook(hook: string): TheGuardHook {
  return LEGACY_HOOK_ALIASES[hook] ?? (hook as TheGuardHook)
}

/**
 * Every native seam a POLICY may bind to — the full interception surface the
 * policy editor offers, including the observe-only lifecycle seams and the
 * monotonic `tools/guard` invariant. Review templates and the baseline scope
 * offer the same 9-hook surface (a model verdict at the observe-only seams is
 * an audit row; at `tools/guard` the sync invariant never runs the model).
 */
export const POLICY_HOOKS: string[] = [
  'tools/pre-execute',
  'tools/post-execute',
  'tools/result',
  'agent/pre-step',
  'agent/turn-stopping',
  'agent/session-start',
  'subagent/start',
  'subagent/end',
  'tools/guard',
]

/** Seams whose verdicts can NEVER interrupt the run (audit-only by design). */
export const OBSERVE_ONLY_HOOKS: readonly string[] = [
  'tools/result',
  'agent/session-start',
  'subagent/start',
  'subagent/end',
]

/** The four guard actions a template's disposition cap may take. */
export type TemplateAction = 'allow' | 'block' | 'ask' | 'warn'

/** All disposition actions, strictest last (the editor's option order). */
export const TEMPLATE_ACTIONS: readonly TemplateAction[] = ['allow', 'block', 'ask', 'warn']

/**
 * Normalize one template's disposition cap: unknown values drop (absent =
 * uncapped, i.e. any parsed action stands), and a cap stricter than the
 * binding allows — block or ask on a binding whose hooks are ALL observe-
 * only, where no verdict can ever interrupt the run — clamps down to `warn`,
 * the strictest verdict that seam can deliver. The audit-only outcome is
 * identical either way, so the clamp only keeps the form and the saved table
 * consistent.
 */
export function normalizeTemplateAction(action: unknown, hooks: readonly TheGuardHook[]): TemplateAction | undefined {
  if (typeof action !== 'string' || !TEMPLATE_ACTIONS.includes(action as TemplateAction)) return undefined
  if (hooks.length > 0 && hooks.every((h) => OBSERVE_ONLY_HOOKS.includes(h)) && (action === 'block' || action === 'ask')) {
    return 'warn'
  }
  return action as TemplateAction
}

/** One custom per-hook review template (client mirror of host ReviewPromptTemplate). */
export interface ReviewTemplateLike {
  /** Stable identity (panel keys + audit rows). */
  id: string
  /** Display name; empty falls back to the id. */
  name: string
  /** The hooks this template reviews — multi-select (empty = runs nowhere). */
  hooks: TheGuardHook[]
  /** @deprecated legacy v0.1.x single-hook binding; read via
   * {@link templateHooksOf} when `hooks` is absent. New saves write the array. */
  hook?: TheGuardHook
  /** Disabled templates are skipped entirely. */
  enabled: boolean
  /** Template text; empty = the template is skipped entirely. */
  prompt: string
  /** Disposition cap: the strictest verdict this template may deliver — a
   * stricter model verdict clamps down to it. Absent = uncapped. */
  action?: TemplateAction
}

/**
 * The hooks one template binds to, canonicalized: the `hooks` array when
 * present, the deprecated single `hook` otherwise; legacy v0.1.x names map to
 * their native seams. Duplicates collapse; order is the template's own order.
 */
export function templateHooksOf(tpl: { hooks?: unknown; hook?: unknown }): TheGuardHook[] {
  const raw = Array.isArray(tpl.hooks)
    ? tpl.hooks
    : tpl.hook !== undefined ? [tpl.hook] : []
  const out: TheGuardHook[] = []
  for (const value of raw) {
    if (typeof value !== 'string' || value.length === 0) continue
    const canonical = canonicalGuardHook(value)
    if (!out.includes(canonical)) out.push(canonical)
  }
  return out
}

/** Client-side mirror of the model-review stage prefs (host `config.ts`). */
export interface ModelReviewPrefsLike {
  enabled: boolean
  mode: 'session' | 'custom'
  /** Post-hoc make-up review switch (session mode; default off). Optional:
   * older hosts may not send it — read with `=== true`. */
  makeupReview?: boolean
  /** Built-in baseline review templates (the three shipped audit prompts).
   * Read-only cards — the panel can only flip each card's `enabled` switch. */
  baselineTemplates?: ReviewTemplateLike[]
  /** Custom per-hook templates; within a hook, array order = priority.
   * Optional: older hosts may not send it. */
  templates?: ReviewTemplateLike[]
  baseUrl: string
  apiKey: string
  model: string
  timeoutMs: number
  /** Wire protocol for the dedicated review endpoint (custom mode). */
  protocol: 'openai-chat' | 'openai-responses' | 'anthropic'
  /** Dedicated-review reasoning setting (custom mode); forwarded as
   * `reasoning_effort` (OpenAI) or `thinking` budget (Anthropic) except
   * `'default'`, which attaches nothing. */
  thinking: 'default' | 'off' | 'low' | 'medium' | 'high'
}

/** GET/POST /guard/api/prefs response (the full user preferences doc). */
export interface GuardPrefsResult {
  /** Preferred panel language; `'auto'` follows the DSH active locale. */
  locale?: GuardLocale
  /** Whether the Security Review tab shows in the conversation view ring. */
  showSessionTab?: boolean
  /** Whether the shield button shows in the session header. */
  showHeaderButton?: boolean
  /** Master switch for the guard engine (off = everything allowed). */
  guardEnabled?: boolean
  /** Whether `allow` verdicts are written to the audit log too. */
  recordAllow?: boolean
  /** Rule-stage switch (pluggable stage #1). */
  rulesEnabled?: boolean
  /** Model-stage switch + config (pluggable stage #2). */
  modelReview?: ModelReviewPrefsLike
  ok?: boolean
  message?: string
  error?: string
}

/** Throw a readable error for a non-2xx response (best-effort message). */
async function failFor(res: Response): Promise<never> {
  let message = `HTTP ${res.status}`
  try {
    const body = (await res.json()) as { error?: { message?: string } } | null
    if (body?.error?.message) message = body.error.message
  } catch {
    // keep the default message
  }
  throw new Error(message)
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(path, { method: 'GET' })
  if (!res.ok) await failFor(res)
  return (await res.json()) as T
}

async function postJson<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method: 'POST',
    headers: body === undefined ? undefined : { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!res.ok) await failFor(res)
  return (await res.json()) as T
}

/** The panel API surface (one method per route). */
export const guardApi = {
  /**
   * Fetch the verdict trail. Pass a session id to narrow the response to that
   * session only (the conversation view tab); pass `after` to receive only rows
   * newer than that seq (incremental cursor, N9). Omit both for the full
   * cross-session aggregate the header panel shows.
   */
  verdicts(sessionId?: string, after?: number): Promise<GuardVerdictRow[]> {
    const parts: string[] = []
    if (sessionId !== undefined) parts.push(`sessionId=${encodeURIComponent(sessionId)}`)
    if (after !== undefined && Number.isFinite(after) && after > 0) parts.push(`after=${after}`)
    const query = parts.length === 0 ? '' : `?${parts.join('&')}`
    return getJson<GuardVerdictRow[]>(`/guard/api/verdicts${query}`)
  },
  clearVerdicts(): Promise<GuardActionResult> {
    return postJson<GuardActionResult>('/guard/api/clear-verdicts')
  },
  getPolicies(): Promise<GuardPoliciesResult> {
    return getJson<GuardPoliciesResult>('/guard/api/policies')
  },
  savePolicies(table: unknown): Promise<GuardActionResult> {
    return postJson<GuardActionResult>('/guard/api/policies', table)
  },
  resetPolicies(): Promise<GuardActionResult> {
    return postJson<GuardActionResult>('/guard/api/reset-policies')
  },
  getLang(): Promise<GuardLangResult> {
    return getJson<GuardLangResult>('/guard/api/lang')
  },
  setLang(locale: GuardLocale): Promise<GuardLangResult> {
    return postJson<GuardLangResult>('/guard/api/lang', { locale })
  },
  /**
   * Seed the host's in-memory resolved locale (the panel's `effectiveLocale()`:
   * an explicit preference, or the DSH active locale in auto mode) so
   * host-generated messages follow it. Re-reported on boot and on change.
   */
  setResolvedLocale(locale: 'zh' | 'en'): Promise<GuardActionResult> {
    return postJson<GuardActionResult>('/guard/api/lang/resolved', { locale })
  },
  getPrefs(): Promise<GuardPrefsResult> {
    return getJson<GuardPrefsResult>('/guard/api/prefs')
  },
  setPrefs(patch: Partial<Pick<GuardPrefsResult, 'locale' | 'showSessionTab' | 'showHeaderButton' | 'guardEnabled' | 'recordAllow' | 'rulesEnabled' | 'modelReview'>>): Promise<GuardPrefsResult> {
    return postJson<GuardPrefsResult>('/guard/api/prefs', patch)
  },
}
