/**
 * Plugin configuration: the policy table plus a few global switches.
 * `tools/pre-execute` = the only hook with an approval seam. `ask` elsewhere
 * degrades to block/reject, which is why the panel locks ask policies to it.
 *
 * The same-named schemastery schema validates injected config before the
 * plugin starts (Cordis resolves `runtime.Config['~standard']`); `apply` then
 * re-checks the semantic invariants that a schema cannot express (a policy
 * with no rules, an unknown operator, …) and fails loud rather than silently
 * degrading.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/config
 */

import z from '@deepseek-ai/schemastery'
import type { GuardAction, GuardOperator, GuardPolicy } from './types.ts'
import type { GuardMode } from './types.ts'
import { canonicalHook, type ReviewTemplateHook } from './hooks.ts'
import { BASELINE_REVIEW_TEMPLATES } from './audit-prompts.ts'

/**
 * Per-hook enable switches, keyed by native harness seam name. Defaults: every
 * hook on. The legacy v0.1.x keys (`beforeToolCall`, `toolResultPersist`,
 * `afterToolCall`, `beforePromptBuild`) are still accepted — a legacy key wins
 * only when its native counterpart is absent (see {@link resolveHookSwitches}).
 */
export interface HookSwitches {
  /** Veto/ask/allow tool calls via `tools/pre-execute`. Default `true`. */
  toolsPreExecute?: boolean
  /** Block or enrich tool results via `tools/post-execute`. Default `true`. */
  toolsPostExecute?: boolean
  /** Observe-only audit trail via `tools/result`. Default `true`. */
  toolsResult?: boolean
  /** Reject proposed model steps via `agent/pre-step`. Default `true`. */
  agentPreStep?: boolean
  /** Review the stop boundary via `agent/turn-stopping`; a block steers a continuation. Default `true`. */
  agentTurnStopping?: boolean
  /** Observe-only session-start audit via `agent/session-start`. Default `true`. */
  agentSessionStart?: boolean
  /** Observe-only subagent lifecycle audit via `subagent/start`+`end`. Default `true`. */
  subagentLifecycle?: boolean
  /** Monotonic deny-only invariant via `ctx.tools.guard()`. Default `true`. */
  toolsGuard?: boolean
  /** Inject the security section via `system-prompt/assemble`. Default `true`. */
  systemPromptAssemble?: boolean
  /** @deprecated legacy v0.1.x key for {@link HookSwitches.toolsPreExecute}. */
  beforeToolCall?: boolean
  /** @deprecated legacy v0.1.x key for {@link HookSwitches.toolsPostExecute}. */
  toolResultPersist?: boolean
  /** @deprecated legacy v0.1.x key for {@link HookSwitches.toolsResult}. */
  afterToolCall?: boolean
  /** @deprecated legacy v0.1.x key for {@link HookSwitches.agentPreStep}. */
  beforePromptBuild?: boolean
}

/**
 * Resolve the effective per-hook switches: native keys first; a legacy key
 * applies only when its native counterpart is absent (old archives that
 * explicitly switched a hook off keep working).
 */
export function resolveHookSwitches(hooks: HookSwitches | undefined): Required<Omit<HookSwitches, 'beforeToolCall' | 'toolResultPersist' | 'afterToolCall' | 'beforePromptBuild'>> {
  const legacy = hooks ?? {}
  return {
    toolsPreExecute: legacy.toolsPreExecute ?? legacy.beforeToolCall ?? true,
    toolsPostExecute: legacy.toolsPostExecute ?? legacy.toolResultPersist ?? true,
    toolsResult: legacy.toolsResult ?? legacy.afterToolCall ?? true,
    agentPreStep: legacy.agentPreStep ?? legacy.beforePromptBuild ?? true,
    agentTurnStopping: legacy.agentTurnStopping ?? true,
    agentSessionStart: legacy.agentSessionStart ?? true,
    subagentLifecycle: legacy.subagentLifecycle ?? true,
    toolsGuard: legacy.toolsGuard ?? true,
    systemPromptAssemble: legacy.systemPromptAssemble ?? true,
  }
}

export interface Config {
  /** Ordered guard policies; first match (priority, then order) wins. Default `[]`. */
  policies?: GuardPolicy[]
  /** Fail-open (allow) vs fail-closed (block) when the engine itself errors. Default `true`. */
  failOpen?: boolean
  /** Include the built-in baseline threat policies. Default `true`. */
  basePolicies?: boolean
  /** Workspace root for path-scoped guards (deletion outside workspace, …). Default: process.cwd(). */
  workspaceRoot?: string
  /** Per-hook enable switches. Default: every hook on. */
  hooks?: HookSwitches
  /** Engine-default posture; `monitor` downgrades block/ask to warn. Default `'protect'`. */
  mode?: GuardMode
  /** Inject the prompt-guard security section into every system prompt. Default `true`. */
  promptGuard?: boolean
  /**
   * Append a localized `notice` user-message to the session when a prompt step
   * is rejected (`agent/pre-step` block/ask), so the conversation gives
   * the user immediate feedback instead of silently swallowing the request.
   * The notice carries only the policy reason, never the blocked content.
   * Default `true`.
   */
  promptBlockNotice?: boolean
}

const OPERATORS = ['eq', 'neq', 'contains', 'in', 'matches', 'regex'] as const satisfies readonly GuardOperator[]
const ACTIONS = ['allow', 'block', 'ask', 'warn'] as const satisfies readonly GuardAction[]

/** One policy row, shared by the injected `Config` and the UI file table. */
const POLICY = z.object({
  id: z.string().required(),
  // Single-hook contract (enforced by the panel UI + validateTable): a policy
  // binds exactly one hook; `tools/pre-execute` is the default and the only
  // hook with an approval seam. `*` / multi-hook values from legacy files are
  // tolerated at load (validatePolicies stays lenient) so old configs keep
  // loading, but new saves through the panel can never produce them. Legacy
  // v0.1.x hook names are accepted and canonicalized by the engine at load.
  hooks: z.array(z.string()).default(['tools/pre-execute']),
  enabled: z.boolean().default(true),
  priority: z.number().default(100),
  rules: z.array(z.object({
    id: z.string(),
    field: z.string().required(),
    operator: z.union([
      z.const('eq'),
      z.const('neq'),
      z.const('contains'),
      z.const('in'),
      z.const('matches'),
      z.const('regex'),
    ]).required(),
    value: z.any(),
  })).default([]),
  action: z.union([
    z.const('allow'),
    z.const('block'),
    z.const('ask'),
    z.const('warn'),
  ]).required(),
  message: z.string(),
  mode: z.union([z.const('protect'), z.const('monitor')]),
})

/**
 * Runtime config schema (Standard Schema via schemastery). Field defaults are
 * applied during validation, so `apply` can read `config.policies`,
 * `config.failOpen`, and `config.hooks` as always-present.
 */
export const Config: z<Config> = z.object({
  policies: z.array(POLICY).default([]),
  failOpen: z.boolean().default(true),
  mode: z.union([z.const('protect'), z.const('monitor')]).default('protect'),
  promptGuard: z.boolean().default(true),
  promptBlockNotice: z.boolean().default(true),
  basePolicies: z.boolean().default(true),
  workspaceRoot: z.string(),
  hooks: z.object({
    toolsPreExecute: z.boolean().default(true),
    toolsPostExecute: z.boolean().default(true),
    toolsResult: z.boolean().default(true),
    agentPreStep: z.boolean().default(true),
    agentTurnStopping: z.boolean().default(true),
    agentSessionStart: z.boolean().default(true),
    subagentLifecycle: z.boolean().default(true),
    toolsGuard: z.boolean().default(true),
    systemPromptAssemble: z.boolean().default(true),
    // Legacy v0.1.x keys: accepted so old archives keep validating; resolved
    // through resolveHookSwitches only when the native key is absent.
    beforeToolCall: z.boolean(),
    toolResultPersist: z.boolean(),
    afterToolCall: z.boolean(),
    beforePromptBuild: z.boolean(),
  }),
})

/**
 * One UI-policy-table file (`ui-policies.json`, written by the panel's
 * dynamic host half, read by `policy-store.ts`). Presence REPLACES the
 * cordis.yml policies wholesale; `reset: true` is the "restore cordis.yml
 * baseline" marker the store honours and then deletes the file.
 */
export interface UiPolicyTable {
  /** Wire-format version; 1 is the only accepted value. */
  v: 1
  /** `true` = restore the cordis.yml baseline (policies ignored). */
  reset: boolean
  /** Full replacement policy table, same shape as `Config.policies`. */
  policies: GuardPolicy[]
}

export const UiPolicyTable: z<UiPolicyTable> = z.object({
  v: z.const(1),
  reset: z.boolean().default(false),
  policies: z.array(POLICY).default([]),
})

/**
 * User-facing Security Guard preferences, persisted through the DSH settings
 * seam (namespace {@link GUARD_PREFS_NS}). The client half reads/writes them
 * over the plugin's own fenced routes (`/guard/api/lang`) because the DSH
 * settings RPC domain only serves allowlisted namespaces; the plugin's routes
 * bridge the browser panel to the in-process settings scope.
 */
/**
 * Model-review stage configuration (pluggable stage #2). The model stage runs
 * AFTER the rule stage in the fixed chain `hook → rules → model → verdict`;
 * it is independent of the rule engine and can be switched on/off per hook.
 *
 * Demo storage note: `apiKey` is kept in the settings document (plaintext).
 * The extension seam is `ModelCaller` / `createModelCaller` in model-review.ts;
 * a later iteration may move the key into the harness `credentials` service.
 */
/** The guard hooks a custom review template can bind to (native seam names). */
export type { ReviewTemplateHook } from './hooks.ts'

/**
 * Schemastery schema for one template-hook binding: accepts every native seam
 * name plus the legacy v0.1.x names, canonicalizing legacy values to their
 * native seams so old persisted prefs keep loading.
 */
function reviewTemplateHookSchema(): z<ReviewTemplateHook> {
  return z.transform(
    z.union([
      z.const('tools/pre-execute'),
      z.const('tools/post-execute'),
      z.const('tools/result'),
      z.const('agent/pre-step'),
      z.const('agent/turn-stopping'),
      z.const('agent/session-start'),
      z.const('subagent/start'),
      z.const('subagent/end'),
      z.const('tools/guard'),
      z.const('before_tool_call'),
      z.const('tool_result_persist'),
      z.const('after_tool_call'),
      z.const('before_prompt_build'),
    ]),
    (value: string): ReviewTemplateHook => canonicalHook(value) as ReviewTemplateHook,
  )
}

/**
 * One custom review prompt template bound to one or more hooks (multi-select
 * chips). The template joins EVERY listed hook's review chain; within each
 * hook the templates array order is the priority. A `block` verdict
 * short-circuits the chain; otherwise verdicts merge strictest-wins.
 */
export interface ReviewPromptTemplate {
  /** Stable identity (panel keys + audit rows). */
  id: string
  /** Display name, e.g. "Data Leakage Review"; empty falls back to the id. */
  name: string
  /** The hooks this template reviews (native seam names; empty = nowhere). */
  hooks: ReviewTemplateHook[]
  /** @deprecated legacy v0.1.x single-hook binding. Not part of the settings
   * schema (schemastery passes it through as an unknown field); read paths
   * fall back to it via {@link resolveTemplateHooks} when `hooks` is absent.
   * New saves always write the array form. */
  hook?: ReviewTemplateHook
  /** Disabled templates are skipped entirely. Default `true`. */
  enabled: boolean
  /**
   * Template text. Placeholders match the global prompt: `{user_query}`
   * `{agent_behavior}` plus the legacy `{hookType}` `{content}`
   * `{rulesVerdict}` `{sessionId}`.
   */
  prompt: string
  /**
   * Disposition cap (custom templates only): the strictest verdict this
   * template may deliver — a stricter model verdict clamps down to it (the
   * parsed reason is kept verbatim). Absent = uncapped, i.e. any action the
   * parser produces stands; `'block'` behaves the same. Baseline templates
   * ignore the field: their action tables are server-fixed per id
   * (model-review.ts category tables), so the panel's baseline disposition
   * dropdown stays read-only.
   */
  action?: GuardAction
}

export interface ModelReviewPrefs {
  /** Master switch for the model stage. Default `false`. */
  enabled: boolean
  /**
   * `session` = reuse the session's current model (`session.requestHeader()`
   * route, dispatched through `ctx.llm`); `custom` = a dedicated OpenAI-
   * compatible endpoint configured below (direct `fetch`).
   */
  mode: 'session' | 'custom'
  /**
   * Post-hoc make-up review for events skipped on the session-mode first-request
   * timing race (route not yet in the session log). Off by default: skipped
   * events just stay skipped (still recorded as `status: 'skipped'`); enabling
   * parks them in a bounded queue and reviews each once the route shows up.
   * Session mode only (a custom endpoint never races).
   */
  makeupReview: boolean
  /**
   * Built-in baseline review templates. Each is a read-only card on the shield
   * panel's Model Review tab — the name, hook binding and prompt text come from
   * {@link BASELINE_REVIEW_TEMPLATES} (Malicious Intent Detection →
   * `agent/pre-step`, Risky Instruction Detection + Intent Drift Detection →
   * `tools/pre-execute`); only `enabled` is
   * user-editable (a disabled baseline card is skipped entirely). The cards
   * cannot be deleted or reordered, and their prompt cannot be edited — to
   * customize, copy the text into a {@link ModelReviewPrefs.templates} entry.
   * Default: the three shipped audit prompts.
   */
  baselineTemplates: ReviewPromptTemplate[]
  /**
   * Custom review templates. Each binds one or more hooks (multi-select);
   * within each hook the array order is the execution priority (top =
   * first). Executed after the baseline templates; verdicts merge
   * strictest-wins and a `block` short-circuits the remaining templates.
   * A template with an empty prompt is skipped entirely.
   */
  templates: ReviewPromptTemplate[]
  /** Custom mode: OpenAI-compatible base URL, e.g. `https://api.deepseek.com/v1`. */
  baseUrl: string
  /** Custom mode: API key. Demo stores it plaintext in the settings document. */
  apiKey: string
  /** Custom mode: model id, e.g. `deepseek-chat`. */
  model: string
  /**
   * Wire protocol used by the dedicated review endpoint (custom mode only).
   * `'openai-chat'` = OpenAI-compatible `/chat/completions` (the default);
   * `'openai-responses'` = OpenAI Responses API `/responses`;
   * `'anthropic'` = Anthropic Messages API `/v1/messages`.
   */
  protocol: 'openai-chat' | 'openai-responses' | 'anthropic'
  /**
   * End-to-end deadline for one model call (ms). Default `12000`. The review
   * is awaited INLINE in the guard decision path (the model verdict can
   * escalate the delivered decision), so this deadline bounds the added
   * latency of a guarded step. The old 3000 ms default starved session-model
   * reviews — most completions, and every reasoning model, exceed it — so
   * reads migrate a persisted `3000` up to `12000` (see
   * {@link reviewTimeoutSchema}).
   */
  timeoutMs: number
  /**
   * Reasoning-chain setting for the dedicated review endpoint. Only
   * meaningful in `custom` mode.
   *
   * OpenAI protocols: `'default'` (the default) attaches nothing and leaves
   * the endpoint's own behavior untouched; `'off'` / `'low'` / `'medium'` /
   * `'high'` are forwarded verbatim as the `reasoning_effort` request field.
   *
   * Anthropic protocol: `'default'` / `'off'` attach no `thinking` block;
   * `'low'` / `'medium'` / `'high'` enable `thinking` with a budget of
   * `1024` / `2048` / `8192` tokens.
   *
   * Endpoints that do not accept the flags will reject the call, so anything
   * other than `'default'` is opt-in.
   */
  thinking: 'default' | 'off' | 'low' | 'medium' | 'high'
}

export interface GuardPrefs {
  /**
   * Preferred panel language. `'auto'` (the default) follows the DSH active
   * locale; `'zh'` / `'en'` force the panel into that language regardless of
   * the host locale.
   */
  locale: 'auto' | 'zh' | 'en'
  /**
   * Whether the "Security Review" tab appears in the conversation view ring
   * (the tab strip next to trajectory). Default `true`.
   */
  showSessionTab: boolean
  /**
   * Whether the shield button shows in the conversation header (the
   * `conversation.session.header.utilities` seat). Default `true`. Toggling
   * this registers/unregisters the seat live, so the button appears or
   * disappears without a reload.
   */
  showHeaderButton: boolean
  /**
   * Master switch for the guard plugin. When `false` the guard is fully off. Every
   * hook short-circuits: no scanning, no blocking/asking, no verdict
   * logging and no system-prompt security section. Default `true`.
   */
  guardEnabled: boolean
  /**
   * Whether `allow` verdicts are written to the audit log too. Disabled by
   * default (allow is the overwhelming majority and low signal); enabling it
   * records every all-clear decision, at the cost of faster log growth.
   */
  recordAllow: boolean
  /**
   * Rule-stage switch (pluggable stage #1). When `false` the rule engine
   * short-circuits to allow (like `guardEnabled`, but scoped to the rule
   * stage only — the model stage still runs when enabled). Default `true`.
   */
  rulesEnabled: boolean
  /** Model-stage switch + configuration (pluggable stage #2). Default disabled. */
  modelReview: ModelReviewPrefs
}

/** The DSH settings namespace holding the Security Guard preferences. */
export const GUARD_PREFS_NS = 'agent-security-guard'

/** Fallback prefs used whenever the settings document is unreachable or malformed. */
export const MODEL_REVIEW_DEFAULTS: ModelReviewPrefs = {
  enabled: false,
  mode: 'session',
  makeupReview: false,
  // Baseline = the three shipped audit prompts: Malicious Intent Detection → agent/pre-step,
  // Risky Instruction Detection + Intent Drift Detection → tools/pre-execute.
  baselineTemplates: BASELINE_REVIEW_TEMPLATES.slice(),
  templates: [],
  baseUrl: '',
  apiKey: '',
  model: '',
  timeoutMs: 12000,
  protocol: 'openai-chat',
  thinking: 'default',
}

/** Fallback prefs used whenever the settings document is unreachable or malformed. */
export const GUARD_PREFS_DEFAULTS: GuardPrefs = {
  locale: 'auto',
  showSessionTab: true,
  showHeaderButton: true,
  guardEnabled: true,
  recordAllow: false,
  rulesEnabled: true,
  modelReview: MODEL_REVIEW_DEFAULTS,
}

/**
 * Five-level reasoning-strength enum. Accepts the legacy boolean archives that
 * older plugins persisted before the enum upgrade (`true` → `'medium'`,
 * `false` → `'default'` — the same mapping `guard-api.ts` applies to fresh
 * patch writes). Without this, a persisted `modelReview.thinking` boolean makes
 * the whole `agent-security-guard` namespace fail schema validation at
 * registration, so every preference edit answers a 500 and silently rolls back
 * on reload.
 */
function reviewThinkingSchema(): z<'default' | 'off' | 'low' | 'medium' | 'high'> {
  return z.transform(
    z.union([
      z.const('default'),
      z.const('off'),
      z.const('low'),
      z.const('medium'),
      z.const('high'),
      z.boolean(),
    ]),
    (value: 'default' | 'off' | 'low' | 'medium' | 'high' | boolean): 'default' | 'off' | 'low' | 'medium' | 'high' => {
      if (value === true) return 'medium'
      if (value === false) return 'default'
      return value
    },
  ).default('default')
}

/**
 * Model-call deadline with a one-way legacy-default migration: installs that
 * persisted the old 3000 ms default are bumped to 12000 ms on read. 3 s
 * starved session-model reviews — most completions, and every reasoning
 * model, exceed it — so the stage recorded "aborted by the timeout deadline"
 * on nearly every attempt. The migration is read-side and idempotent: the
 * next panel patch write persists the bumped value. A user who truly wants
 * ~3 s can set `3001` (or any other value), which passes through untouched.
 */
function reviewTimeoutSchema(): z<number> {
  return z.transform(
    z.number(),
    (value: number): number => (value === 3000 ? 12000 : value),
  ).default(12000)
}

/** Runtime user-preference schema (schemastery; registered by the host half). */
export const GuardPrefs: z<GuardPrefs> = z.object({
  locale: z.union([z.const('auto'), z.const('zh'), z.const('en')]).default('auto'),
  showSessionTab: z.boolean().default(true),
  showHeaderButton: z.boolean().default(true),
  guardEnabled: z.boolean().default(true),
  recordAllow: z.boolean().default(false),
  rulesEnabled: z.boolean().default(true),
  modelReview: z.object({
    enabled: z.boolean().default(false),
    mode: z.union([z.const('session'), z.const('custom')]).default('session'),
    makeupReview: z.boolean().default(false),
    baselineTemplates: z.array(z.object({
      id: z.string().required(),
      name: z.string().default(''),
      // Multi-hook binding (new). A template with an empty list runs nowhere.
      // The deprecated legacy single `hook` field is intentionally NOT declared
      // here: schemastery passes unknown fields through, so v0.1.x archives
      // carrying `hook` survive schema validation untouched, while new saves
      // only ever write `hooks` (the guard-api patch path accepts both).
      hooks: z.array(reviewTemplateHookSchema()).default([]),
      enabled: z.boolean().default(true),
      prompt: z.string().default(''),
    })).default(MODEL_REVIEW_DEFAULTS.baselineTemplates),
    templates: z.array(z.object({
      id: z.string().required(),
      name: z.string().default(''),
      // Multi-hook binding (new). A template with an empty list runs nowhere.
      // The deprecated legacy single `hook` field is intentionally NOT declared
      // here: schemastery passes unknown fields through, so v0.1.x archives
      // carrying `hook` survive schema validation untouched, while new saves
      // only ever write `hooks` (the guard-api patch path accepts both).
      hooks: z.array(reviewTemplateHookSchema()).default([]),
      enabled: z.boolean().default(true),
      prompt: z.string().default(''),
      // The disposition cap (`action`) is intentionally NOT declared here —
      // same reasoning as the legacy `hook` above: schemastery passes unknown
      // fields through untouched. The strict validation lives in the
      // guard-api prefs patch (the only write path); the engine treats an
      // unknown value as uncapped (fail-safe, never fail closed).
    })).default(MODEL_REVIEW_DEFAULTS.templates),
    baseUrl: z.string().default(''),
    apiKey: z.string().default(''),
    model: z.string().default(''),
    timeoutMs: reviewTimeoutSchema(),
    protocol: z.union([z.const('openai-chat'), z.const('openai-responses'), z.const('anthropic')]).default('openai-chat'),
    thinking: reviewThinkingSchema(),
  }).default(MODEL_REVIEW_DEFAULTS),
})

/**
 * Semantic validation that a schema cannot express. Called from `apply` before
 * any listener is registered; throws on the first violation (fail loud, never
 * a silent fall-back).
 */
export function validatePolicies(policies: GuardPolicy[]): void {
  for (const policy of policies) {
    if (!policy.id) {
      throw new Error('agent-security-guard: every policy must have a non-empty `id`')
    }
    if (!Array.isArray(policy.rules) || policy.rules.length === 0) {
      throw new Error(`agent-security-guard: policy "${policy.id}" must declare at least one rule`)
    }
    for (const rule of policy.rules) {
      if (!rule.field) {
        throw new Error(`agent-security-guard: policy "${policy.id}" has a rule without a \`field\``)
      }
      if (!OPERATORS.includes(rule.operator as GuardOperator)) {
        throw new Error(`agent-security-guard: policy "${policy.id}" has unknown operator "${String(rule.operator)}"`)
      }
      if (rule.operator === 'in' && !Array.isArray(rule.value)) {
        throw new Error(`agent-security-guard: policy "${policy.id}" rule on "${rule.field}" uses \`in\` but \`value\` is not an array`)
      }
    }
    if (!ACTIONS.includes(policy.action as GuardAction)) {
      throw new Error(`agent-security-guard: policy "${policy.id}" has unknown action "${String(policy.action)}"`)
    }
  }
}
