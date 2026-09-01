/**
 * Domain types for the local security-guard decision engine.
 *
 * Plain TypeScript local decision logic, no out-of-process runtime.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/types
 */

import type { HookType } from './hooks.ts'
export type { HookType, ReviewTemplateHook } from './hooks.ts'
export { canonicalHook, REVIEW_TEMPLATE_HOOKS } from './hooks.ts'

/** Decision action the engine can emit. */
export type GuardAction = 'allow' | 'block' | 'ask' | 'warn'

/**
 * Posture of a policy (or the engine default): `monitor` downgrades
 * `block`/`ask` verdicts to `warn`, so the guard records what it would have
 * stopped without ever stopping it. Default `protect`.
 */
export type GuardMode = 'protect' | 'monitor'

/**
 * Supported comparison operators. `eq`/`neq` use strict identity; `contains`
 * is substring containment over strings; `in` expects `value` to be an array;
 * `matches` is a `*`-wildcard glob over strings (every other regex
 * metacharacter is matched literally).
 */
export type GuardOperator = 'eq' | 'neq' | 'contains' | 'in' | 'matches' | 'regex'

/** One comparison condition. */
export interface GuardRule {
  /** Stable rule id, surfaced in audit logs (optional). */
  id?: string
  /**
   * Field to inspect. Built-ins: `eventType`, `agentId`, `agentType`,
   * `content`. Anything else resolves against the flattened event `data` first
   * (`toolName`, `arguments`, and every primitive tool-argument field), then
   * against the ambient `context`.
   */
  field: string
  operator: GuardOperator
  /** Expected value. For `in`, an array; for `matches`, a glob pattern. */
  value: unknown
}

/** One guard policy: a set of rules bound to an action. */
export interface GuardPolicy {
  /** Stable policy id, surfaced as the matched rule and in audit logs. */
  id: string
  /**
   * Hook types (native harness seam names, e.g. `tools/pre-execute`) this
   * policy applies to. `'*'` (or `['*']`) matches every hook; glob patterns
   * (`tools/*`) are accepted. Legacy v0.1.x names (`before_tool_call`, …) are
   * canonicalized to their native seams at load. Default `['tools/pre-execute']`.
   */
  hooks?: string[]
  /** Whether the policy is active. Default `true`. */
  enabled?: boolean
  /**
   * Higher priority wins when several policies match the same hook. Ties are
   * broken by declaration order. Default `100`.
   */
  priority?: number
  /** Posture override; `monitor` downgrades block/ask to warn. Default: engine default (`protect`). */
  mode?: GuardMode
  /**
   * ANY rule matching triggers the policy (OR semantics).
   */
  rules: GuardRule[]
  /** Action taken when the policy matches. */
  action: GuardAction
  /** Human-readable reason rendered into deny/ask/warn messages. */
  message?: string
}

/**
 * A normalized event handed to the engine. The adapter flattens each harness
 * payload into this shape, so rules never depend on harness internals.
 */
export interface GuardEvent {
  eventType: HookType | string
  /** The caller agent's id (also the session id in deepseek-harness). */
  agentId?: string
  /** Reserved. deepseek-harness has no per-agent "type"; rules usually target `agentId` instead. */
  agentType?: string
  /** Pre-extracted model/tool text (tool command, prompt text, …). */
  content?: string
  sessionId?: string
  turn?: number
  step?: number
  /** Flattened event payload: `toolName`, `arguments`, primitive argument fields, … */
  data: Record<string, unknown>
  /** Ambient context (caller agent id, …). */
  context: Record<string, unknown>
}

/** The engine's verdict for one event. */
export interface GuardDecision {
  action: GuardAction
  /**
   * The winning policy id first, followed by the ids of every rule of that
   * policy that matched (audit trail). Empty when nothing matched.
   */
  matchedRules: string[]
  /** Reason carried into deny/ask/warn messages. */
  message: string
  /** True when a monitor-mode policy downgraded block/ask to warn. */
  monitorDowngraded?: boolean
  /** The winning policy id, if any. */
  policyId?: string
  /**
   * Which review stage produced the final action: `rule` (rule engine only),
   * `model` (model stage alone), or `both` (both stages ran and merged).
   * Absent for legacy rows and allow-by-default fallbacks.
   */
  source?: 'rule' | 'model' | 'both'
  /** The model stage's verdict, when the model stage ran (audit trail). */
  modelVerdict?: ModelVerdict
}

/**
 * One model-stage review verdict, parsed from the model's raw output by a
 * {@link ModelVerdictParser}. The parser seam is the extension point: the demo
 * ships a lenient JSON parser, later versions may swap in structured output,
 * function-calling or a different schema without touching the engine.
 */
export interface ModelVerdict {
  action: GuardAction
  /** Human-readable reason produced by the model. */
  reason: string
  /** Model-reported confidence in 0..1 (optional; demo models may omit it). */
  confidence?: number
  /** Raw model output as received (audit trail; bounded by the model stage). */
  raw?: string
}

/**
 * The review model that served one model-review request. For `session` mode
 * the harness session route (`provider` / `model`) is recorded; for `custom`
 * mode the configured endpoint. Kept attrs-only so the client can render it
 * without importing the harness.
 */
export interface ModelReviewProvider {
  /** `'session'` = the session's current model; `'custom'` = dedicated endpoint. */
  mode: 'session' | 'custom'
  /** Session-mode provider id (e.g. `deepseek`). */
  provider?: string
  /** Session-mode model id (e.g. `deepseek-chat`). */
  model?: string
  /** Custom-mode endpoint base URL. */
  baseUrl?: string
}

/**
 * One model-review attempt, emitted by the model stage (observability seam)
 * and persisted by {@link audit.recordModelReview}. Unlike the merged
 * {@link GuardDecision}, this row keeps the stage-level detail: which model
 * served the request, the rendered review prompt (request body), the raw
 * model output (response body), and whether the output parsed.
 */
export interface ModelReviewRecord {
  /** The owner agent/session id. `undefined` degrades to a no-op. */
  sessionId?: string
  /** The guard hook that triggered the review (`tools/pre-execute`, …). */
  hook: string
  /**
   * `'ok'` = parsed verdict; `'error'` = call failed or output unparseable;
   * `'skipped'` = not attempted at all (session mode: the session model route
   * was not resolvable yet — the first-request timing race; the event is
   * queued for a post-hoc make-up review instead of failing loudly).
   */
  status: 'ok' | 'error' | 'skipped'
  /** The parsed verdict action (`ok` rows only). */
  action?: GuardAction
  /** The model's reason (`ok` rows only). */
  reason?: string
  /** The model-reported confidence, 0..1 (`ok` rows only). */
  confidence?: number
  /** Which model served the review (session route / custom endpoint). */
  provider?: ModelReviewProvider
  /** The rendered review prompt handed to the model (request body, bounded). */
  request?: string
  /** The raw model output (response body, bounded). */
  response?: string
  /** Wall-clock duration of the model call (ms). */
  durationMs?: number
  /** Failure detail when `status` is `'error'`. */
  error?: string
  /** Why the attempt was skipped / that it is a post-hoc make-up (skipped + late rows). */
  note?: string
  /** True on a post-hoc make-up row: reviewed after the fact; its verdict was
   * recorded for audit only and did NOT affect the already-delivered decision. */
  late?: boolean
  /** Context: the tool being reviewed (when the event carries one). */
  tool?: string
  /** Context: the harness call id the review belongs to (when available). */
  callId?: string
  /** Context: turn / step the review belongs to. */
  turn?: number
  step?: number
  /**
   * Which review template produced this record: the baseline template's name
   * (`default`) or the custom template's display name (falls back to its id).
   * Absent only on the skip marker for events that never reached a template.
   */
  template?: string
}
