/**
 * Guard hook names — the native deepseek-harness extension-point seams.
 *
 * The guard binds its policies, its audit rows and its review templates to the
 * harness's NATIVE seam names (`ctx.on` event names), one-to-one — there is no
 * plugin-internal aliasing vocabulary on the wire anymore. Each hook maps onto
 * the harness extension point it subscribes to:
 *
 * Verdict-capable seams (the listener's decision affects the run):
 *   - `tools/pre-execute`   — veto / ask / allow a tool call (`PreToolDecision`;
 *                             the ONLY seam with an approval channel for `ask`)
 *   - `tools/post-execute`  — block or enrich a tool result (`PostToolDecision`)
 *   - `agent/pre-step`      — reject a proposed model step (`PreStepDecision`)
 *   - `agent/turn-stopping` — steer a continuation at the stop boundary
 *                             (awaited notification; block/ask steer with the
 *                             reason, self-capped per turn)
 *   - `tools/guard`         — the monotonic `ctx.tools.guard()` invariant
 *                             (deny-only, rule stage only, runs after the whole
 *                             pre-execute waterfall)
 *
 * Observe-only seams (audit trail, never veto):
 *   - `tools/result`        — final tool outcome snapshot
 *   - `agent/session-start` — session lifecycle start (notification only)
 *   - `subagent/start`      — subagent run started (notification only)
 *   - `subagent/end`        — subagent run settled (notification only)
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/hooks
 */

/**
 * The verdict-capable subset of {@link HookType}: seams where a model/rule
 * verdict can affect the run. Reference metadata (UI hints, tests); bindings
 * are declared over the full {@link POLICY_HOOKS} surface.
 */
export const REVIEW_TEMPLATE_HOOKS = [
  'tools/pre-execute',
  'tools/post-execute',
  'agent/pre-step',
  'agent/turn-stopping',
] as const satisfies readonly HookType[]

/** Every hook this guard can intercept, named by its native harness seam. */
export type HookType =
  | 'tools/pre-execute'
  | 'tools/post-execute'
  | 'tools/result'
  | 'agent/pre-step'
  | 'agent/turn-stopping'
  | 'agent/session-start'
  | 'subagent/start'
  | 'subagent/end'
  | 'tools/guard'

/**
 * Every seam a review template (baseline or custom) can bind to: all 9 native
 * seams. A model verdict has an effect at the verdict-capable seams; at the
 * observe-only lifecycle seams (`tools/result`, `agent/session-start`,
 * `subagent/*`) the review still RUNS — the full pipeline is registered there —
 * but its verdict is recorded to the audit trail only, never interrupting the
 * run (the same posture a POLICY bound to those seams has). `tools/guard` is
 * the one seam where a model binding is inert: the invariant is synchronous
 * and rule-stage only, so the model stage never runs there.
 */
export type ReviewTemplateHook = HookType

/**
 * Every native seam a POLICY may bind to — the full interception surface the
 * policy editor offers. Includes the observe-only lifecycle seams (a verdict
 * there only records to the audit trail) and the monotonic `tools/guard`
 * invariant (only a `block` verdict has an effect: deny; `ask` is pinned to
 * `tools/pre-execute` by the single-hook contract anyway).
 */
export const POLICY_HOOKS: readonly HookType[] = [
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

/**
 * The hooks one review template binds to, canonicalized: the multi-hook
 * `hooks` array when present (legacy single `hook` otherwise), every value
 * run through {@link canonicalHook}, deduplicated. New saves always write
 * `hooks`; v0.1.x archives carry the single `hook` field and keep loading.
 * Returned as plain canonical strings so callers can match against any hook
 * spelling without casting.
 */
export function resolveTemplateHooks(template: { hooks?: unknown; hook?: unknown }): string[] {
  const raw = Array.isArray(template.hooks)
    ? template.hooks
    : template.hook !== undefined ? [template.hook] : []
  const out: string[] = []
  for (const value of raw) {
    if (typeof value !== 'string' || value.length === 0) continue
    const canonical = canonicalHook(value)
    if (!out.includes(canonical)) out.push(canonical)
  }
  return out
}

/** Seams whose verdicts can NEVER interrupt the run (audit-only by design). */
export const OBSERVE_ONLY_HOOKS: ReadonlySet<string> = new Set([
  'tools/result',
  'agent/session-start',
  'subagent/start',
  'subagent/end',
])

/**
 * Hooks with an approval seam, where `ask` waits on the human instead of
 * degrading. `tools/pre-execute` is the only one (`agent/pre-step` and
 * `tools/post-execute` have no ask surface; `agent/turn-stopping` degrades to
 * a steer).
 */
export const APPROVAL_SEAM_HOOKS: ReadonlySet<string> = new Set(['tools/pre-execute'])

/**
 * Legacy plugin-internal hook names (v0.1.x) mapped onto their native seams.
 * Policies, persisted prefs and audit rows written by older builds keep
 * loading: every read path canonicalizes through {@link canonicalHook}, and
 * every write path (panel saves) emits native names.
 */
export const LEGACY_HOOK_ALIASES: Readonly<Record<string, HookType>> = {
  before_tool_call: 'tools/pre-execute',
  tool_result_persist: 'tools/post-execute',
  after_tool_call: 'tools/result',
  before_prompt_build: 'agent/pre-step',
}

/** All accepted hook spellings (native + legacy), for schema unions. */
export const KNOWN_HOOK_NAMES: readonly string[] = [
  ...Object.values(LEGACY_HOOK_ALIASES),
  ...Object.keys(LEGACY_HOOK_ALIASES),
]

/**
 * Canonicalize a hook name: legacy plugin-internal names become their native
 * seam; native names pass through; anything else passes through unchanged so
 * unknown/forward values never crash a read path.
 */
export function canonicalHook(hook: string): string {
  return LEGACY_HOOK_ALIASES[hook] ?? hook
}

/** Whether a canonical hook may carry an `ask` verdict with a live approval seam. */
export function hasApprovalSeam(hook: string): boolean {
  return APPROVAL_SEAM_HOOKS.has(canonicalHook(hook))
}
