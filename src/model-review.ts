/**
 * Model review stage: the pluggable second stage of the guard chain
 * `hook → rules → model → verdict`.
 *
 * Everything the model stage needs from the outside is behind a seam, so the
 * demo wiring can be swapped without touching the engine:
 *
 *   - {@link ModelVerdictParser} — model output → {@link ModelVerdict}.
 *     Shipped: {@link AuditRiskModelVerdictParser}, which reads the
 *     two-dimension risk shape the built-in template asks for and falls
 *     through to {@link JsonModelVerdictParser} for the legacy
 *     `{action, reason, confidence}` object hand-written prompts still use.
 *     Later: structured output / function-calling — swap the factory.
 *   - {@link ModelCaller} — one review prompt → raw text. Demo:
 *     {@link SessionModelCaller} (reuses the session model via `ctx.llm`) and
 *     {@link HttpModelCaller} (direct OpenAI-compatible `fetch`). Later:
 *     retry/streaming/provider adapters — swap the factory.
 *
 * {@link ModelReviewEngine} runs the rule stage first, then the model stage,
 * and merges with the pure {@link mergeVerdicts} policy. Every model-stage
 * failure fails open to the rule verdict (same posture as the rule engine).
 */

import { BlockAssembler, createUserMessage } from '@deepseek-ai/dsh-llm'
import type { GenerateOptions, StreamChunk } from '@deepseek-ai/dsh-llm'
import type { ModelReviewPrefs } from './config.ts'
import { canonicalHook, resolveTemplateHooks } from './hooks.ts'
import type { GuardAction, GuardDecision, GuardEvent, GuardMode, ModelReviewProvider, ModelReviewRecord, ModelVerdict } from './types.ts'

export type { ModelVerdict } from './types.ts'

const PREFIX = '[agent-security-guard]'

/** Upper bound on the raw model output persisted on a verdict (audit size). */
const MAX_RAW_CHARS = 2_000
/** Upper bound on the rendered review prompt handed to the model. */
const MAX_PROMPT_CHARS = 32_000

/**
 * Bounded queue of events awaiting a post-hoc make-up review. In `session`
 * mode a session's FIRST guarded event races the harness's `request/header`
 * logging (the header snapshot is appended inside the step before dispatch,
 * i.e. AFTER the guard hook runs), so its route is not resolvable yet. Such
 * events are recorded as `status: 'skipped'`, parked here, and reviewed once
 * a later event observes a ready route — capped so a long route-less stretch
 * cannot grow memory.
 */
const MAX_PENDING_MAKEUP = 16

/** Why a row was skipped instead of reviewed (shown on the record + panel). */
const SKIP_NOTE
  = 'session model route not yet available: the harness appends the request header '
    + '(with provider/model) to the session log only when it dispatches the first request, '
    + 'so the first guarded event of a session races it. Decision fell through to the rules '
    + 'stage and the event was queued for a post-hoc make-up review'

/** Annotation stamped onto every post-hoc make-up review record. */
const MAKEUP_NOTE
  = 'post-hoc make-up review of an event skipped on first-request timing; '
    + 'audit-only — this verdict did NOT affect the already-delivered decision'

/** Prompt placeholder context rendered by {@link renderReviewPrompt}. */
export interface ReviewPromptContext {
  /** The hook that produced the event (`tools/pre-execute`, …). */
  hookType: string
  /** The content being reviewed (bounded by the stage). */
  content: string
  /** User-role message text, when the event carries it (e.g. prompt-build hooks). */
  userQuery?: string
  /** What the agent produced or attempted: tool call, prompt, result (bounded). */
  agentBehavior?: string
  /** The rule stage's verdict summary (e.g. `allow`, `block: reason`). */
  rulesVerdict: string
  /** Session id, when available. */
  sessionId?: string
  /** The language the review reason should be written in (`Chinese` | `English`),
   * resolved from the panel/UI language. Rendered into the `{reason_lang}`
   * placeholder; default `English` when absent. */
  reasonLang?: string
}

/**
 * Render a review prompt template; unknown placeholders pass through. The
 * built-in template renders `{user_query}` (user-role text),
 * `{agent_behavior}` (the event content under review) and `{reason_lang}`
 * (the reason-line language, from {@link ReviewPromptContext.reasonLang}); the
 * legacy `{hookType}` `{content}` `{rulesVerdict}` `{sessionId}` placeholders
 * stay supported for custom templates.
 */
export function renderReviewPrompt(template: string, ctx: ReviewPromptContext): string {
  const params: Record<string, string> = {
    hookType: ctx.hookType,
    content: ctx.content,
    user_query: ctx.userQuery ?? '',
    agent_behavior: ctx.agentBehavior ?? ctx.content,
    rulesVerdict: ctx.rulesVerdict,
    sessionId: ctx.sessionId ?? '',
    reason_lang: ctx.reasonLang ?? 'English',
  }
  let out = template
  for (const [name, value] of Object.entries(params)) {
    out = out.replaceAll(`{${name}}`, value)
  }
  return out
}

/**
 * The output-parser seam: one verdict from the model's raw output, or `null`
 * when unusable (fail-safe). Swap the implementation (and the
 * {@link ModelVerdict} shape if needed) without touching the engine.
 */
export interface ModelVerdictParser {
  parse(raw: string): ModelVerdict | null
}

/**
 * The legacy single-object parser: locates the LAST balanced JSON object
 * (reasoning-capable models often narrate their thinking first and emit the
 * verdict JSON at the very end; earlier `{...}` mentions are usually the shape
 * reminder or a draft), tolerating markdown fences and trailing prose, then
 * validates `action` (one of the four guard actions) and a non-empty `reason`;
 * `confidence` is optional, 0..1. Any defect returns `null` → the stage fails
 * open to the rule verdict. Still the parser for prompts written against that
 * shape; {@link AuditRiskModelVerdictParser} delegates to it.
 */
export class JsonModelVerdictParser implements ModelVerdictParser {
  parse(raw: string): ModelVerdict | null {
    if (typeof raw !== 'string') return null
    const candidate = extractLastJsonObject(raw)
    if (candidate === null) return null
    let parsed: unknown
    try {
      parsed = JSON.parse(candidate)
    } catch {
      return null
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null
    const record = parsed as { action?: unknown; reason?: unknown; confidence?: unknown }
    const { action, reason } = record
    if (action !== 'allow' && action !== 'block' && action !== 'ask' && action !== 'warn') return null
    if (typeof reason !== 'string' || reason.trim().length === 0) return null
    const verdict: ModelVerdict = { action, reason: reason.trim() }
    const confidence = record.confidence
    if (typeof confidence === 'number' && Number.isFinite(confidence) && confidence >= 0 && confidence <= 1) {
      verdict.confidence = confidence
    }
    return verdict
  }
}

/**
 * Verdict severity, strictest to most lenient. Shared by the audit parser (to
 * pick the strictest matched risk category) and by {@link mergeVerdicts} (to
 * pick the strictest stage), so "stricter" means the same thing in both.
 */
const SEVERITY: Record<GuardAction, number> = { block: 3, ask: 2, warn: 1, allow: 0 }

/** The strictest of two actions. */
function stricter(a: GuardAction, b: GuardAction): GuardAction {
  return SEVERITY[b] > SEVERITY[a] ? b : a
}

/** Upper bound on the verdict reason (it becomes the audit row + notice text). */
const MAX_REASON_CHARS = 600

/** The category the built-in template asks for when a dimension is clean. */
const NO_RISK_CATEGORY = 'No Risk'

/**
 * Which action each `user_request_risks` category implies.
 *
 * This dimension is adversarial *input* — an attempted jailbreak, an injected
 * document, a probe. It stays advisory (`warn`) because a block on
 * `agent/pre-step` rejects the user's message outright (no approval seam
 * exists there, so even `ask` degrades to a reject), and injected text is not
 * evidence the agent did anything. The two exceptions are attempts to switch
 * the guard or its configuration off: that is the same threat the rule engine
 * already blocks on intent, so the model stage agrees instead of softening it.
 */
const USER_REQUEST_RISK_ACTIONS: Record<string, GuardAction> = {
  'Instruction Override / Jailbreak Attempt': 'block',
  'Configuration Tampering Inducement': 'block',
  'Role Impersonation Attempt': 'warn',
  'Indirect Prompt Injection': 'warn',
  'Tool Output Injection': 'warn',
  'Session / Context Probing': 'warn',
  'Agent Memory Access Inducement': 'warn',
  'Workspace Escape Inducement': 'warn',
  'PII Disclosure Intent': 'warn',
  'Business Secret Disclosure Intent': 'warn',
  'Cross-Tenant Disclosure Intent': 'warn',
  [NO_RISK_CATEGORY]: 'allow',
}

/**
 * Which action each `agent_behavior_risks` category implies.
 *
 * This dimension is what the agent actually did or attempted, so it carries
 * the enforcement: confirmed disclosure and irreversible/destructive actions
 * block, while actions that are frequently legitimate (external egress,
 * dependency installs, config writes, suspicious parameters) escalate to a
 * human. On `tools/pre-execute` the harness renders `ask` as an approval
 * prompt; at post-execute and pre-step there is no approval seam, so the host
 * withholds the result / rejects the step with the reason as feedback.
 */
const AGENT_BEHAVIOR_RISK_ACTIONS: Record<string, GuardAction> = {
  'PII Disclosure': 'block',
  'Business Secret Disclosure': 'block',
  'Cross-Tenant Disclosure': 'block',
  'Destructive Command': 'block',
  'Privilege Escalation / Permission Relaxation': 'block',
  'Sandbox Escape Attempt': 'block',
  'Dangerous Tool Call': 'block',
  'System Path Write': 'ask',
  'External Network Connection': 'ask',
  'Malicious Dependency Installation': 'ask',
  'Tool Parameter Manipulation': 'ask',
  [NO_RISK_CATEGORY]: 'allow',
}

/** Category names are matched case/padding-insensitively (models re-flow them). */
function normalizeCategory(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/g, ' ').replace(/[.。;；,，]+$/, '')
}

function toActionMap(table: Record<string, GuardAction>): Map<string, GuardAction> {
  const out = new Map<string, GuardAction>()
  for (const [name, action] of Object.entries(table)) out.set(normalizeCategory(name), action)
  return out
}

const USER_REQUEST_ACTIONS = toActionMap(USER_REQUEST_RISK_ACTIONS)
const AGENT_BEHAVIOR_ACTIONS = toActionMap(AGENT_BEHAVIOR_RISK_ACTIONS)

/** Malicious Intent Detection (USER_REQUEST_RISK_PROMPT): the category table
 * for the two-line output.
 * Input-side (adversarial user text) → advisory `warn`, guard-bypass /
 * configuration tampering block like the JSON audit table above. */
const USER_REQUEST_LINE_ACTIONS: Record<string, GuardAction> = {
  'Instruction Override / Jailbreak Inducement': 'block',
  'Configuration Tampering Inducement': 'block',
  'Role Impersonation Inducement': 'warn',
  'Indirect Prompt Injection': 'warn',
  'Tool Output Injection': 'warn',
  'Conversation / Context Probing': 'warn',
  'Agent Memory Extraction Inducement': 'warn',
  'Workspace Escape Inducement': 'warn',
  'PII Leakage Intent': 'warn',
  'Confidential Business Information Leakage Intent': 'warn',
  'Cross-Tenant Data Leakage Intent': 'warn',
  [NO_RISK_CATEGORY]: 'allow',
}

/** Risky Instruction Detection (AGENT_BEHAVIOR_RISK_PROMPT): the category
 * table for the two-line output.
 * Agent-side (what it attempted/executed) → enforcement, same split as the
 * JSON audit table: confirmed disclosure / destructive block, boundary actions
 * ask, suspicious params warn-adjacent ask on the approval seam. */
const AGENT_BEHAVIOR_LINE_ACTIONS: Record<string, GuardAction> = {
  'PII Leakage': 'block',
  'Confidential Business Information Leakage': 'block',
  'Cross-Tenant Data Leakage': 'block',
  'Destructive Command': 'block',
  'Privilege Escalation / Permission Weakening': 'block',
  'Sandbox Escape Attempt': 'block',
  'Dangerous Tool Invocation': 'block',
  'System Path Write': 'ask',
  'Network Egress': 'ask',
  'Malicious Dependency Installation': 'ask',
  'Tool Parameter Manipulation': 'ask',
  [NO_RISK_CATEGORY]: 'allow',
}

/** Intent Drift Detection (INTENT_DRIFT_PROMPT): No Drift → allow; Intent
 * Drift → ask (human confirmation; tools/pre-execute is the only hook with
 * an approval seam). */
const INTENT_DRIFT_ACTIONS: Record<string, GuardAction> = {
  'No Drift': 'allow',
  'Intent Drift': 'ask',
}

/** Combined one-line categories → action, shared by the line parser. */
const LINE_ACTIONS = new Map<string, GuardAction>()
for (const table of [USER_REQUEST_LINE_ACTIONS, AGENT_BEHAVIOR_LINE_ACTIONS, INTENT_DRIFT_ACTIONS]) {
  for (const [name, action] of Object.entries(table)) LINE_ACTIONS.set(normalizeCategory(name), action)
}

/** One dimension of the audit output: its risk array, its evidence field, its table. */
interface RiskDimension {
  readonly risksKey: string
  readonly reasonKey: string
  readonly label: string
  readonly actions: Map<string, GuardAction>
  /** The other dimension's table, tried on a miss: a category name means the
   * same thing wherever the model filed it. */
  readonly other: Map<string, GuardAction>
}

const AUDIT_DIMENSIONS: RiskDimension[] = [
  {
    risksKey: 'user_request_risks',
    reasonKey: 'user_request_reason',
    label: 'user request',
    actions: USER_REQUEST_ACTIONS,
    other: AGENT_BEHAVIOR_ACTIONS,
  },
  {
    risksKey: 'agent_behavior_risks',
    reasonKey: 'agent_behavior_reason',
    label: 'agent behavior',
    actions: AGENT_BEHAVIOR_ACTIONS,
    other: USER_REQUEST_ACTIONS,
  },
]

/**
 * The shipped parser for the built-in audit template's two-dimension output:
 *
 * ```json
 * { "user_request_risks": [...], "user_request_reason": "...",
 *   "agent_behavior_risks": [...], "agent_behavior_reason": "..." }
 * ```
 *
 * Each category maps to a guard action through the tables above; the verdict
 * is the strictest one across both dimensions, and the reason names every
 * matched category followed by the model's own evidence, so the audit row and
 * the in-conversation notice say *why* the review fired. Lenient on purpose
 * (models ignore formatting): a bare string counts as a one-item array, `No
 * Risk` loses to any real category listed beside it, and a category the tables
 * don't know becomes a `warn` carrying its verbatim name so an operator can
 * extend the table. Falls through to {@link JsonModelVerdictParser} when the
 * object carries neither dimension, keeping hand-written prompts that still
 * ask for `{action, reason, confidence}` working. A dimension that is present
 * but structurally unusable (not a string/array) rejects the whole object: a
 * half-malformed verdict is not a verdict, and the stage fails open to rules.
 */
export class AuditRiskModelVerdictParser implements ModelVerdictParser {
  private readonly legacy = new JsonModelVerdictParser()

  parse(raw: string): ModelVerdict | null {
    if (typeof raw !== 'string') return null
    const candidate = extractLastJsonObject(raw)
    if (candidate === null) return null
    let parsed: unknown
    try {
      parsed = JSON.parse(candidate)
    } catch {
      return null
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null
    const record = parsed as Record<string, unknown>
    const present = AUDIT_DIMENSIONS.filter((dimension) => record[dimension.risksKey] !== undefined)
    if (present.length === 0) return this.legacy.parse(raw)

    let action: GuardAction = 'allow'
    const parts: string[] = []
    for (const dimension of present) {
      const categories = categoriesOf(record[dimension.risksKey])
      if (categories === null) return null
      const matched = categories.filter((category) => normalizeCategory(category) !== normalizeCategory(NO_RISK_CATEGORY))
      if (matched.length === 0) continue
      for (const category of matched) {
        const key = normalizeCategory(category)
        action = stricter(action, dimension.actions.get(key) ?? dimension.other.get(key) ?? 'warn')
      }
      const evidence = record[dimension.reasonKey]
      const evidenceText = typeof evidence === 'string' ? evidence.trim() : ''
      const names = matched.map((category) => category.trim()).join(', ')
      parts.push(`${dimension.label} [${names}]${evidenceText.length > 0 ? `: ${evidenceText}` : ''}`)
    }
    const reason = parts.length > 0 ? parts.join('; ') : 'no risk categories detected'
    return { action, reason: reason.length > MAX_REASON_CHARS ? `${reason.slice(0, MAX_REASON_CHARS - 1)}…` : reason }
  }
}

/** The category list of one dimension, or `null` when the value is unusable. */
function categoriesOf(value: unknown): string[] | null {
  if (typeof value === 'string') return [value]
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
  return null
}

/**
 * The shipped parser for the three two-line baseline audit prompts
 * (`USER_REQUEST_RISK_PROMPT` / `AGENT_BEHAVIOR_RISK_PROMPT` /
 * `INTENT_DRIFT_PROMPT`): Line 1 = one category, Line 2 = a concise reason.
 *
 * The model is told to output exactly two lines, but in practice it narrates
 * first (reasoning models think aloud) and may wrap the verdict in fences. So
 * the parser scans from the END for the LAST line that matches a known
 * category — the final verdict line, reasoning-chain and drafts ignored — and
 * treats the remainder after it as the evidence (the reason line the template
 * asked for). Any line that matches a known category counts, so a category
 * never requires a fixed position.
 *
 * Each category maps to a guard action through the combined table
 * ({@link USER_REQUEST_LINE_ACTIONS} ∪ {@link AGENT_BEHAVIOR_LINE_ACTIONS} ∪
 * {@link INTENT_DRIFT_ACTIONS}); `block` is the strictest, `ask` carries the
 * approval seam on `tools/pre-execute`, `No Risk` / `No Drift` allow. A
 * category the table doesn't know becomes a `warn` carrying its verbatim name
 * so an operator can extend the table — same posture as the JSON audit parser.
 * Returns `null` when no category line can be found (fail-safe → rule verdict).
 */
export class LineRiskModelVerdictParser implements ModelVerdictParser {
  parse(raw: string): ModelVerdict | null {
    if (typeof raw !== 'string') return null
    const lines = rawToLines(raw)
    if (lines.length === 0) return null
    // Last matching category line wins: a later real verdict outranks earlier
    // narration or a draft mention of a category name.
    let hit = -1
    for (let i = lines.length - 1; i >= 0; i -= 1) {
      if (LINE_ACTIONS.has(normalizeCategory(lines[i] as string))) {
        hit = i
        break
      }
    }
    if (hit === -1) {
      // No known category: honor the template's strict two-line contract — Line
      // 1 IS the category, so a structurally two-line verdict with an unknown
      // category name surfaces as a `warn` (verbatim name, tunable) instead of
      // being silently swallowed. A single prose line (or narration) is not a
      // verdict shape → `null` (fail open to the rule verdict).
      if (lines.length < 2) return null
      const unknown = lines[0] as string
      const evidence = lines.slice(1).join(' ').trim()
      return {
        action: 'warn',
        reason: `${unknown}${evidence.length > 0 ? `: ${evidence}` : ''}`,
      }
    }
    const category = lines[hit]!.trim()
    const action = LINE_ACTIONS.get(normalizeCategory(category)) ?? 'warn'
    const evidence = lines.slice(hit + 1).join(' ').trim()
    const reason = action === 'allow'
      ? ''
      : `${category}${evidence.length > 0 ? `: ${evidence}` : ''}`
    return { action, reason: reason.length > MAX_REASON_CHARS ? `${reason.slice(0, MAX_REASON_CHARS - 1)}…` : reason }
  }
}

/** Split raw model output into trimmed, non-empty logical lines, stripping a
 * surrounding markdown fence if present (the template says "no Markdown" but
 * models wrap nonetheless). */
function rawToLines(raw: string): string[] {
  let text = raw.trim()
  const fence = /^```(?:json|text)?\s*$/i
  if (fence.test(text)) {
    const idx = text.indexOf('\n')
    text = idx === -1 ? '' : text.slice(idx + 1)
  }
  const trailing = text.indexOf('\n```')
  if (trailing !== -1) text = text.slice(0, trailing)
  text = text.trim()
  const out: string[] = []
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (trimmed.length > 0) out.push(trimmed)
  }
  return out
}

/**
 * The composite parser wired into the production stage: tries the JSON audit
 * parser first (the two-dimension audit shape and any custom JSON-format
 * template), then the two-line parser (the three baseline audit prompts). A
 * JSON verdict and a two-line verdict are mutually exclusive shapes,
 * so the order is unambiguous. When neither shape parses, both return `null`
 * and the stage fails open to the rule verdict.
 */
export class CompositeModelVerdictParser implements ModelVerdictParser {
  private readonly auditParser = new AuditRiskModelVerdictParser()
  private readonly lineParser = new LineRiskModelVerdictParser()

  parse(raw: string): ModelVerdict | null {
    return this.auditParser.parse(raw) ?? this.lineParser.parse(raw)
  }
}

/**
 * Extract the LAST balanced `{...}` object from text (string-aware), in stream
 * order. A model that thinks aloud may emit intermediate `{...}` fragments; the
 * final one is the response to act on. `null` when no balanced object exists.
 */
function extractLastJsonObject(text: string): string | null {
  const out: Array<{ start: number; end: number }> = []
  let inString = false
  let escaped = false
  let depth = 0
  let startedAt = -1
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]
    if (inString) {
      if (escaped) {
        escaped = false
      } else if (ch === '\\') {
        escaped = true
      } else if (ch === '"') {
        inString = false
      }
      continue
    }
    if (ch === '"') {
      inString = true
      continue
    }
    if (ch === '{') {
      if (depth === 0) startedAt = i
      depth += 1
      continue
    }
    if (ch === '}') {
      depth -= 1
      if (depth === 0 && startedAt !== -1) {
        out.push({ start: startedAt, end: i + 1 })
        startedAt = -1
      }
    }
  }
  if (out.length === 0) return null
  const last = out[out.length - 1]!
  return text.slice(last.start, last.end)
}

/** What one model call needs, in caller-neutral terms. */
export interface ModelCallSpec {
  /** The rendered review prompt (user turn). */
  prompt: string
  /** Optional system instruction. */
  system?: string
  /** Session id, when available. */
  sessionId?: string
  /** Cancellation (the stage applies its deadline). */
  signal?: AbortSignal
  /** Session model route (`mode: 'session'` only), resolved per event. */
  route?: { provider?: string; model?: string }
}

/** The model-caller seam: one review prompt → raw text. Errors bubble up;
 * the stage catches them and fails open to the rule verdict. */
export interface ModelCaller {
  call(spec: ModelCallSpec): Promise<string>
}

/** The subset of the harness `llm` service the session caller needs. */
export interface LlmLike {
  stream(options: GenerateOptions): AsyncIterable<StreamChunk>
}

/** Demo caller #1: reuse the session's current model via `ctx.llm`. */
export class SessionModelCaller implements ModelCaller {
  constructor(private readonly llm: LlmLike | undefined) {}

  async call(spec: ModelCallSpec): Promise<string> {
    if (this.llm === undefined) throw new Error('llm service unavailable')
    const { provider, model } = spec.route ?? {}
    if (provider === undefined || model === undefined) {
      throw new Error(
        'no session model route available (requestHeader has no provider/model); '
        + 'use the custom mode with a configured endpoint, or pick a provider/model for this session',
      )
    }
    const options: GenerateOptions = {
      provider,
      model,
      messages: [
        createUserMessage({
          content: [{ type: 'text', text: spec.prompt }],
          source: { kind: 'plugin', plugin: 'agent-security-guard' },
        }),
      ],
      // Reasoning-capable session models (e.g. a local Qwen served by vLLM)
      // spend tokens on a thinking chain before the verdict JSON; 512 often
      // ends mid-thought with no JSON at all. Give the review room to finish.
      maxTokens: 2048,
      ...(spec.system !== undefined ? { system: spec.system } : {}),
      // `sessionId` is branded `SessionId`; the event id is a plain string.
      ...(spec.sessionId !== undefined ? { sessionId: spec.sessionId as never } : {}),
      ...(spec.signal !== undefined ? { signal: spec.signal } : {}),
    }
    const assembler = new BlockAssembler()
    for await (const chunk of this.llm.stream(options)) {
      assembler.push(chunk)
    }
    // LlmRuntime normalizes adapter/transport failures to a TERMINAL finish
    // chunk (`kind: 'error' | 'aborted'`, carrying an `LlmFailure`) instead of
    // throwing. Without this check the real cause — most often the stage's
    // deadline aborting the stream mid-flight — is swallowed and an empty
    // stream degrades to the misleading "produced no text". Surface it.
    const finish = assembler.finish
    if (finish.kind === 'error' || finish.kind === 'aborted') {
      // Our own deadline (AbortSignal.timeout in the stage) is the common
      // abort cause — name it so the fix (raise the review timeout) is obvious.
      if (finish.kind === 'aborted' && spec.signal?.aborted === true) {
        throw new Error('session model review aborted by the timeout deadline: ' + finish.failure.message)
      }
      throw new Error(`session model stream ${finish.kind}: ${finish.failure.message}`)
    }
    const blocks = assembler.blocks()
    const text = blocks
      .filter((block): block is Extract<(typeof blocks)[number], { type: 'text' }> => block.type === 'text')
      .map((block) => block.text)
      .join(' ')
      .trim()
    if (text.length === 0) {
      // All output tokens spent before any text block arrived: with a
      // reasoning session model the whole budget typically went to thinking.
      if (finish.kind === 'max-tokens') {
        throw new Error('session model hit the max-tokens budget before producing text (a reasoning model may have spent it all on thinking)')
      }
      throw new Error('session model produced no text')
    }
    return text
  }
}

/** Demo caller #2: a dedicated OpenAI-compatible endpoint via direct `fetch`. */
export class HttpModelCaller implements ModelCaller {
  constructor(
    private readonly baseUrl: string,
    private readonly apiKey: string,
    private readonly model: string,
    private readonly thinking: ReviewThinkingLevel,
  ) {}

  async call(spec: ModelCallSpec): Promise<string> {
    const endpoint = `${this.baseUrl.replace(/\/+$/, '')}/chat/completions`
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(this.apiKey.length > 0 ? { authorization: `Bearer ${this.apiKey}` } : {}),
      },
      body: JSON.stringify({
        model: this.model,
        messages: [
          ...(spec.system !== undefined && spec.system.length > 0 ? [{ role: 'system', content: spec.system }] : []),
          { role: 'user', content: spec.prompt },
        ],
        stream: false,
        // Dedicated-review "thinking" setting: any value other than
        // `'default'` is forwarded verbatim as the OpenAI-compatible
        // `reasoning_effort` flag, so `off`/`low`/`medium`/`high` all behave
        // as their name says — and `temperature` is OMITTED there, because
        // reasoning endpoints (o-series etc.) reject the parameter. `'default'`
        // attaches the deterministic temperature 0 and nothing else, keeping
        // the endpoint's own behavior (and old endpoints that would reject an
        // unknown field) untouched.
        ...(this.thinking !== 'default' ? { reasoning_effort: this.thinking } : { temperature: 0 }),
      }),
      ...(spec.signal !== undefined ? { signal: spec.signal } : {}),
    })
    if (!response.ok) {
      const detail = await response.text().catch(() => '')
      throw new Error(`model endpoint responded ${response.status}: ${detail.slice(0, 300)}`)
    }
    const body = (await response.json()) as { choices?: Array<{ message?: { content?: unknown } }> }
    const content = body.choices?.[0]?.message?.content
    if (typeof content !== 'string' || content.trim().length === 0) {
      throw new Error('model endpoint returned no text content')
    }
    return content
  }
}

/** Reasoning setting shared by all dedicated review callers. */
export type ReviewThinkingLevel = 'default' | 'off' | 'low' | 'medium' | 'high'

/** OpenAi Responses API budget for each reasoning level. */
const THINKING_BUDGET_TOKENS: Record<Exclude<ReviewThinkingLevel, 'default' | 'off'>, number> = {
  low: 1024,
  medium: 2048,
  high: 8192,
}

/** Reasoning levels the Responses API accepts as `reasoning.effort`. */
type ReviewReasoningEffort = Exclude<ReviewThinkingLevel, 'default' | 'off'>

/**
 * Responses-API params for a reasoning level. The protocol takes
 * `reasoning: { effort }` — the chat-completions `reasoning_effort` flag is
 * not part of it, and `'off'` is not a valid effort (there is no way to
 * disable reasoning here), so `default`/`off` attach nothing and keep the
 * deterministic temperature. Real reasoning levels omit `temperature`: the
 * reasoning endpoints reject the parameter outright.
 */
function responsesReasoningParams(level: ReviewThinkingLevel): { temperature?: number; reasoning?: { effort: ReviewReasoningEffort } } {
  if (level === 'low' || level === 'medium' || level === 'high') return { reasoning: { effort: level } }
  return { temperature: 0 }
}

/** Demo caller #3: OpenAI Responses API via direct `fetch`. */
export class OpenAiResponsesCaller implements ModelCaller {
  constructor(
    private readonly baseUrl: string,
    private readonly apiKey: string,
    private readonly model: string,
    private readonly thinking: ReviewThinkingLevel,
  ) {}

  async call(spec: ModelCallSpec): Promise<string> {
    const endpoint = `${this.baseUrl.replace(/\/+$/, '')}/responses`
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(this.apiKey.length > 0 ? { authorization: `Bearer ${this.apiKey}` } : {}),
      },
      body: JSON.stringify({
        model: this.model,
        input: [
          ...(spec.system !== undefined && spec.system.length > 0 ? [{ role: 'system', content: spec.system }] : []),
          { role: 'user', content: spec.prompt },
        ],
        stream: false,
        ...responsesReasoningParams(this.thinking),
      }),
      ...(spec.signal !== undefined ? { signal: spec.signal } : {}),
    })
    if (!response.ok) {
      const detail = await response.text().catch(() => '')
      throw new Error(`model endpoint responded ${response.status}: ${detail.slice(0, 300)}`)
    }
    const data = (await response.json()) as {
      output_text?: unknown
      output?: Array<{ type?: unknown; output_text?: unknown } & { content?: Array<{ type?: unknown; text?: unknown }> }>
    }
    const text = extractResponsesText(data)
    if (text.length === 0) throw new Error('model endpoint returned no text content')
    return text
  }
}

/**
 * Pull assistant text out of a Responses-API payload (output_text or message parts).
 */
function extractResponsesText(data: {
  output_text?: unknown
  output?: Array<{ type?: unknown; output_text?: unknown } & { content?: Array<{ type?: unknown; text?: unknown }> }>
}): string {
  if (typeof data.output_text === 'string' && data.output_text.trim().length > 0) return data.output_text.trim()
  if (!Array.isArray(data.output)) return ''
  const parts: string[] = []
  for (const item of data.output) {
    if (item?.type === 'message' && Array.isArray(item.content)) {
      for (const part of item.content) {
        if (part?.type === 'output_text' && typeof part.text === 'string' && part.text.trim().length > 0) parts.push(part.text.trim())
      }
    } else if (typeof item?.output_text === 'string' && item.output_text.trim().length > 0) {
      parts.push(item.output_text.trim())
    }
  }
  return parts.join(' ').trim()
}

/** Demo caller #4: Anthropic Messages API via direct `fetch`. */
export class AnthropicCaller implements ModelCaller {
  constructor(
    private readonly baseUrl: string,
    private readonly apiKey: string,
    private readonly model: string,
    private readonly thinking: ReviewThinkingLevel,
  ) {}

  async call(spec: ModelCallSpec): Promise<string> {
    const base = this.baseUrl.replace(/\/+$/, '')
    const endpoint = `${base.endsWith('/v1') ? base : `${base}/v1`}/messages`
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(this.apiKey.length > 0 ? { 'x-api-key': this.apiKey } : {}),
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: this.model,
        ...anthropicThinkingParams(this.thinking),
        ...(spec.system !== undefined && spec.system.length > 0 ? { system: spec.system } : {}),
        messages: [{ role: 'user', content: spec.prompt }],
      }),
      ...(spec.signal !== undefined ? { signal: spec.signal } : {}),
    })
    if (!response.ok) {
      const detail = await response.text().catch(() => '')
      throw new Error(`model endpoint responded ${response.status}: ${detail.slice(0, 300)}`)
    }
    const data = (await response.json()) as { content?: Array<{ type?: unknown; text?: unknown }> }
    const text = (Array.isArray(data.content) ? data.content : [])
      .filter((part) => part?.type === 'text' && typeof part.text === 'string')
      .map((part) => (part.text as string).trim())
      .filter((value) => value.length > 0)
      .join(' ')
      .trim()
    if (text.length === 0) throw new Error('model endpoint returned no text content')
    return text
  }
}

/** The Anthropic `thinking` block for a reasoning level (`off`/`default` → none). */
/**
 * Anthropic Messages API params for a reasoning level. Two hard API
 * constraints shape the thinking variants: `temperature` must be 1 while
 * thinking is enabled, and `max_tokens` must be STRICTLY greater than
 * `thinking.budget_tokens` (equal is a 400). Violating either kills the whole
 * review request, so budget + 2048 headroom keeps every level coherent.
 */
function anthropicThinkingParams(level: ReviewThinkingLevel): {
  max_tokens: number
  temperature: number
  thinking?: { type: 'enabled'; budget_tokens: number }
} {
  if (level === 'default' || level === 'off') return { max_tokens: 2048, temperature: 0 }
  const budget = THINKING_BUDGET_TOKENS[level]
  return { max_tokens: budget + 2048, temperature: 1, thinking: { type: 'enabled', budget_tokens: budget } }
}

/** What the caller factory needs (llm service; session mode only). */
export interface ModelCallerDeps {
  /** The harness `llm` service. Absent → session mode fails open. */
  llm?: LlmLike
}

/**
 * Build the demo caller for a config: `session` mode reuses the session's
 * current model; `custom` mode talks to the configured endpoint using the
 * selected wire protocol (`openai-chat` / `openai-responses` / `anthropic`).
 * This factory is the seam where later callers plug in.
 */
export function createModelCaller(config: ModelReviewPrefs, deps: ModelCallerDeps): ModelCaller {
  if (config.mode === 'session') {
    return new SessionModelCaller(deps.llm)
  }
  if (config.baseUrl.trim().length === 0 || config.model.trim().length === 0) {
    // Throwing caller → the stage catches it and fails open.
    return { call: async () => { throw new Error('custom model not configured (baseUrl/model empty)') } }
  }
  const baseUrl = config.baseUrl.trim()
  const apiKey = config.apiKey.trim()
  const model = config.model.trim()
  const thinking = config.thinking
  if (config.protocol === 'openai-responses') return new OpenAiResponsesCaller(baseUrl, apiKey, model, thinking)
  if (config.protocol === 'anthropic') return new AnthropicCaller(baseUrl, apiKey, model, thinking)
  return new HttpModelCaller(baseUrl, apiKey, model, thinking)
}

/** One executable entry of a hook's review chain: a display name + a template. */
interface ChainEntry {
  name: string
  template: string
  /** Disposition cap (custom templates only): the strictest action the
   * template's verdict may deliver — a stricter model verdict clamps down to
   * it (the parsed reason is kept verbatim). Absent = uncapped. Baselines
   * never carry one: their action tables are server-fixed per id. */
  cap?: GuardAction
}

/** The four guard actions a template disposition cap may take. */
const TEMPLATE_ACTIONS: readonly string[] = ['allow', 'block', 'ask', 'warn']

/** Type guard for a persisted cap value: anything else = uncapped. */
function isTemplateAction(value: unknown): value is GuardAction {
  return typeof value === 'string' && TEMPLATE_ACTIONS.includes(value)
}

/** Build the bounded content sent to the model for one event. */
function eventContent(event: GuardEvent, truncate: (text: string) => string): string {
  if (typeof event.content === 'string' && event.content.length > 0) return truncate(event.content)
  const args = event.data.arguments
  if (typeof args === 'string' && args.length > 0) return truncate(args)
  try {
    return truncate(JSON.stringify(event.data))
  } catch {
    return ''
  }
}

/**
 * Extract user-role message text from a guard event payload. For prompt-build
 * events the adapter stores the canonicalized messages in `data.messages`;
 * tool-hook events (where the intent-drift / risk-instruction templates need a
 * user request to compare against) carry a pre-extracted `data.userQuery`
 * string feed by the adapter. Absent or empty → `''`.
 */
function userQueryOf(data: Record<string, unknown>): string {
  const preextracted = data.userQuery
  if (typeof preextracted === 'string' && preextracted.length > 0) return preextracted
  const raw = data.messages
  if (typeof raw !== 'string' || raw.length === 0) return ''
  let messages: unknown
  try {
    messages = JSON.parse(raw)
  } catch {
    return ''
  }
  if (!Array.isArray(messages)) return ''
  const parts: string[] = []
  for (const message of messages) {
    if (message === null || typeof message !== 'object') continue
    const role = (message as { role?: unknown }).role
    if (role !== 'user') continue
    const content = (message as { content?: unknown }).content
    if (Array.isArray(content)) {
      for (const block of content) {
        if (block !== null && typeof block === 'object'
          && (block as { type?: unknown }).type === 'text'
          && typeof (block as { text?: unknown }).text === 'string') {
          parts.push((block as { text: string }).text)
        }
      }
    } else if (typeof content === 'string') {
      parts.push(content)
    }
  }
  return parts.join('\n')
}

/** One-sentence summary of the rule verdict for the prompt. */
function ruleVerdictSummary(decision: GuardDecision | null): string {
  if (decision === null) return 'not evaluated (rule stage disabled)'
  const policy = decision.policyId !== undefined ? ` [${decision.policyId}]` : ''
  return `${decision.action}${policy}: ${decision.message}`
}

/** The model-stage seam consumed by {@link ModelReviewEngine}. Implementations
 * decide when active and produce one verdict per event; failures → `null`. */
export interface ModelStage {
  enabled(): boolean
  evaluate(event: GuardEvent, ruleDecision?: GuardDecision | null, route?: SessionRoute | undefined): Promise<ModelVerdict | null>
}

/** Minimal face of the harness session model route (from `requestHeader().config`). */
export interface SessionRoute {
  provider?: string
  model?: string
}

/** Dependencies of the demo {@link DefaultModelStage}. */
export interface DefaultModelStageDeps {
  /** Live model-review config (re-read per event so settings apply instantly). */
  config(): ModelReviewPrefs
  /** The model-caller factory (see {@link createModelCaller}); re-invoked per
   * event so a settings change (mode / endpoint / key) applies instantly. */
  caller: () => ModelCaller
  /** The output parser (see {@link createModelVerdictParser}). */
  parser: ModelVerdictParser
  /** Per-event session model route resolver (`mode: 'session'`); provided by
   * the host (adapter) which holds the agent/session handle. Explicit per-event
   * routes passed to `evaluate` take precedence over this resolver. */
  sessionRoute?: () => SessionRoute | undefined
  /** Content bounder; defaults to a local 32k cap. */
  truncate?: (text: string) => string
  /**
   * The panel/UI language, resolved lazily so a live locale switch takes
   * effect on the very next review. Drives the `{reason_lang}` placeholder so
   * the model writes its reason line in the user's language (zh → Chinese,
   * anything else → English). Absent → English.
   */
  lang?: () => 'zh' | 'en'
  /**
   * Per-attempt observability seam: fired with one {@link ModelReviewRecord}
   * after every model-review call (success or failure), so the host can
   * persist / stream the stage's procedure — provider, request body, response
   * body, duration, error. Optional; absent → the stage stays silent (its
   * behavior before this seam existed).
   */
  onReview?: (record: ModelReviewRecord) => void
}

/** One event parked while its session route raced the first dispatch; retried later. */
interface PendingMakeupReview {
  event: GuardEvent
  ruleDecision: GuardDecision | null
}

/**
 * Demo model stage: for each event it assembles the hook's review chain (the
 * baseline template first, then the hook's custom templates in array order),
 * runs each template (render → call under deadline → parse), short-circuits on
 * a `block`, and merges the verdicts strictest-wins. Any failure fails open
 * per template so the rule verdict stays authoritative.
 *
 * Session-mode first-request race: when `mode: 'session'` and no route can be
 * resolved yet (see {@link SKIP_NOTE}), the event is NOT an error — it emits a
 * `status: 'skipped'` record (fail-open, silent in the host log). Queuing the
 * event for an async post-hoc make-up review is opt-in (`makeupReview`, off by
 * default); when enabled, records are flagged `late: true` — audit-only, the
 * delivered decision was never changed by it.
 */
export class DefaultModelStage implements ModelStage {
  private readonly deps: DefaultModelStageDeps
  /** Events waiting for the session route to show up (bounded, in-memory). */
  private readonly pendingMakeup: PendingMakeupReview[] = []
  /** Re-entrancy guard for the async drain (one drain loop at a time). */
  private drainingMakeup = false
  /** Last ready session route observed on a live evaluation; make-ups use it
   * when the per-event resolver cannot provide anything newer. */
  private lastReadyRoute: SessionRoute | undefined

  constructor(deps: DefaultModelStageDeps) {
    this.deps = deps
  }

  enabled(): boolean {
    return this.deps.config().enabled
  }

  async evaluate(
    event: GuardEvent,
    ruleDecision?: GuardDecision | null,
    route?: SessionRoute | undefined,
  ): Promise<ModelVerdict | null> {
    if (!this.enabled()) return null
    const config = this.deps.config()
    const truncate = this.deps.truncate ?? defaultTruncate
    if (eventContent(event, truncate).length === 0) return null

    const resolvedRoute = route ?? this.deps.sessionRoute?.()
    if (
      typeof resolvedRoute?.provider === 'string' && resolvedRoute.provider.length > 0
      && typeof resolvedRoute.model === 'string' && resolvedRoute.model.length > 0
    ) {
      // Route ready: remember it so later make-ups always have somewhere to go.
      this.lastReadyRoute = resolvedRoute
    } else if (config.mode === 'session') {
      // Session mode with no resolvable route — the first-request timing race.
      // Skip silently (no throw, no warn spam) and leave an observable record;
      // the rule verdict stays in charge. The post-hoc make-up is OPT-IN
      // (`makeupReview`, default off): with it on the event parks in a bounded
      // queue and gets one audit-only review once a later event sees the route.
      this.emitSkippedRecord(event)
      if (config.makeupReview === true) {
        this.pendingMakeup.push({ event, ruleDecision: ruleDecision ?? null })
        if (this.pendingMakeup.length > MAX_PENDING_MAKEUP) this.pendingMakeup.shift()
      }
      return null
    }

    const verdict = await this.runAttempt(event, ruleDecision ?? null, resolvedRoute)
    // Fire-and-forget: flushing must not extend the current hook's latency,
    // and the drained reviews are explicitly non-enforcing (`late: true`).
    void this.drainMakeup()
    return verdict
  }

  /** Emit the skip marker for one event whose session route was not resolvable. */
  private emitSkippedRecord(event: GuardEvent): void {
    const record: ModelReviewRecord = { status: 'skipped', hook: event.eventType, note: SKIP_NOTE }
    if (event.sessionId !== undefined) record.sessionId = event.sessionId
    if (typeof event.data.toolName === 'string') record.tool = event.data.toolName
    if (typeof event.data.callId === 'string') record.callId = event.data.callId
    if (event.turn !== undefined) record.turn = event.turn
    if (event.step !== undefined) record.step = event.step
    this.deps.onReview?.(record)
  }

  /** Drain the make-up queue (one at a time, newest-capacity FIFO); no-ops when
   * already draining or disabled — leftovers are retried on the next evaluate. */
  private async drainMakeup(): Promise<void> {
    if (this.drainingMakeup || this.pendingMakeup.length === 0) return
    this.drainingMakeup = true
    try {
      while (this.pendingMakeup.length > 0 && this.enabled()) {
        const item = this.pendingMakeup.shift()
        if (item === undefined) break
        await this.runAttempt(item.event, item.ruleDecision, this.lastReadyRoute, true)
      }
    } finally {
      this.drainingMakeup = false
    }
  }

  /** One model-call attempt (live or post-hoc): run the hook's template chain. */
  private async runAttempt(
    event: GuardEvent,
    ruleDecision: GuardDecision | null,
    route?: SessionRoute | undefined,
    late = false,
  ): Promise<ModelVerdict | null> {
    const config = this.deps.config()
    const truncate = this.deps.truncate ?? defaultTruncate
    const content = eventContent(event, truncate)
    if (content.length === 0) return null
    const chain = this.chainFor(config, event.eventType)
    if (chain.length === 0) return null
    const collected: Array<{ name: string; verdict: ModelVerdict }> = []
    for (const entry of chain) {
      const verdict = await this.callTemplate(event, entry, ruleDecision, route, late)
      if (verdict === null) continue
      if (verdict.action === 'block') {
        // Short-circuit: block is the strictest verdict — later templates can
        // never out-do it, so skip the rest (saves tokens + latency).
        return this.mergeChainVerdicts([{ name: entry.name, verdict }], chain.length > 1)
      }
      collected.push({ name: entry.name, verdict })
    }
    return this.mergeChainVerdicts(collected, chain.length > 1)
  }

  /**
   * The hook's review chain: the enabled baseline templates bound to this
   * hook first (in {@link ModelReviewPrefs.baselineTemplates} order), then the
   * hook's enabled custom templates in array order (= the priority). An empty
   * chain means the hook is not model-reviewed at all (no baseline card for
   * this hook + no custom templates) — the stage stays silent and the rule
   * verdict stands. A template with an empty prompt is skipped entirely.
   */
  private chainFor(config: ModelReviewPrefs, hookType: string): ChainEntry[] {
    const chain: ChainEntry[] = []
    const canonical = canonicalHook(hookType)
    // Chain builder shared by the baseline cards and the custom templates:
    // appends an entry for a template that binds this hook, is enabled and has
    // non-empty prompt text (a blank prompt never reaches the model). Only
    // custom templates read the disposition cap — the baselines' action
    // tables are server-fixed.
    const append = (template: { id: string; name: string; hooks: unknown; hook?: unknown; enabled: boolean; prompt: string; action?: unknown }, capped: boolean): void => {
      if (template.enabled === false) return
      if (template.prompt.trim().length === 0) return
      // Canonicalize both sides: persisted templates may carry legacy v0.1.x
      // hook names, and the event hook is always native. Multi-hook bindings
      // match every listed hook.
      if (!resolveTemplateHooks(template).includes(canonical)) return
      const named = template.name.trim().length > 0 ? template.name.trim() : template.id.trim()
      chain.push({
        name: named.length > 0 ? named : `template-${chain.length}`,
        template: template.prompt,
        ...(capped && isTemplateAction(template.action) ? { cap: template.action } : {}),
      })
    }
    const baselines = Array.isArray(config.baselineTemplates) ? config.baselineTemplates : []
    for (const template of baselines) {
      if (template === null || typeof template !== 'object') continue
      append(template, false)
    }
    const templates = Array.isArray(config.templates) ? config.templates : []
    for (const template of templates) {
      if (template === null || typeof template !== 'object') continue
      append(template, true)
    }
    return chain
  }

  /**
   * Strictest-wins merge of the chain's verdicts: the final action is the
   * strictest collected one, and the reason joins every verdict that shares
   * it (`[template name] reason`) so the audit row says which template fired. A
   * single-entry chain keeps the bare reason (no prefix noise), which also
   * preserves the pre-chain audit format for baseline-only configurations.
   */
  private mergeChainVerdicts(
    collected: Array<{ name: string; verdict: ModelVerdict }>,
    multi: boolean,
  ): ModelVerdict | null {
    if (collected.length === 0) return null
    let best = collected[0]!
    for (const item of collected) {
      if (SEVERITY[item.verdict.action] > SEVERITY[best.verdict.action]) best = item
    }
    const winners = collected.filter((item) => item.verdict.action === best.verdict.action)
    const first = winners[0]!.verdict
    let reason = first.reason
    if (multi) {
      reason = winners.map((item) => `[${item.name}] ${item.verdict.reason}`).join('; ')
    }
    return {
      action: best.verdict.action,
      reason: reason.length > MAX_REASON_CHARS ? `${reason.slice(0, MAX_REASON_CHARS - 1)}…` : reason,
      ...(first.confidence !== undefined ? { confidence: first.confidence } : {}),
      ...(first.raw !== undefined ? { raw: first.raw } : {}),
    }
  }

  /** One template's model call: render → call → parse → record (fail-open). */
  private async callTemplate(
    event: GuardEvent,
    entry: ChainEntry,
    ruleDecision: GuardDecision | null,
    route?: SessionRoute | undefined,
    late = false,
  ): Promise<ModelVerdict | null> {
    const config = this.deps.config()
    const truncate = this.deps.truncate ?? defaultTruncate
    const content = eventContent(event, truncate)
    if (content.length === 0) return null
    const prompt = renderReviewPrompt(entry.template, {
      hookType: event.eventType,
      content,
      // The new audit-style built-in template analyses both sides of the
      // guard event: user-role text (when the event carries the messages,
      // e.g. prompt-build hooks) and the agent behavior under review (the
      // tool call / prompt / result). Tool-hook events carry no user text,
      // so `user_query` degrades to an empty field, which the template
      // classifies as "No Risk".
      userQuery: truncate(userQueryOf(event.data)),
      agentBehavior: content,
      rulesVerdict: ruleVerdictSummary(ruleDecision ?? null),
      ...(event.sessionId !== undefined ? { sessionId: event.sessionId } : {}),
      // The reason line follows the panel language (zh → Chinese). Live
      // locale switches apply on the next call: lang() is resolved per call.
      reasonLang: this.deps.lang?.() === 'zh' ? 'Chinese' : 'English',
    })
    const boundedPrompt = prompt.length > MAX_PROMPT_CHARS ? prompt.slice(0, MAX_PROMPT_CHARS) : prompt

    // The schema migrates the old 3000 ms default to 12000 on read; this
    // fallback only covers a config face without a numeric timeoutMs.
    const timeoutMs = Number.isFinite(config.timeoutMs) && config.timeoutMs > 0 ? config.timeoutMs : 12000
    let signal: AbortSignal | undefined
    try {
      signal = AbortSignal.timeout(timeoutMs)
    } catch {
      signal = undefined
    }
    const startedAt = Date.now()
    const resolvedRoute = route ?? this.deps.sessionRoute?.()
    const provider = providerOf(config, resolvedRoute)
    // One fired record per attempt: unlike the merged rule verdict, the model
    // stage's procedure (whom it asked, what it sent, what came back) is
    // surfaced here even when the outcome is allow or a misparse.
    const onReview = (status: ModelReviewRecord['status'], patch: Partial<Omit<ModelReviewRecord, 'status'>> = {}): void => {
      const base: ModelReviewRecord = { status, hook: event.eventType, request: boundedPrompt, template: entry.name }
      // `exactOptionalPropertyTypes` forbids assigning `undefined` to an
      // optional property; only attach present fields.
      if (provider !== undefined) base.provider = provider
      if (event.sessionId !== undefined) base.sessionId = event.sessionId
      if (typeof event.data.toolName === 'string') base.tool = event.data.toolName
      if (typeof event.data.callId === 'string') base.callId = event.data.callId
      if (event.turn !== undefined) base.turn = event.turn
      if (event.step !== undefined) base.step = event.step
      this.deps.onReview?.({
        ...base,
        ...patch,
        ...(late ? { late: true, note: MAKEUP_NOTE } : {}),
      })
    }
    let raw: string
    try {
      raw = await this.deps.caller().call({
        prompt: boundedPrompt,
        ...(event.sessionId !== undefined ? { sessionId: event.sessionId } : {}),
        ...(signal !== undefined ? { signal } : {}),
        ...(resolvedRoute !== undefined ? { route: resolvedRoute } : {}),
      })
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      onReview('error', { error: detail, durationMs: Date.now() - startedAt })
      console?.warn?.(`${PREFIX} model review failed, falling back to rule verdict: ${detail}`)
      return null
    }
    const parsed = this.deps.parser.parse(raw)
    const durationMs = Date.now() - startedAt
    if (parsed === null) {
      onReview('error', { error: 'model output not parseable', response: raw, durationMs })
      return null
    }
    // Disposition cap: a verdict stricter than the template's configured cap
    // clamps down to it (the model's reason is kept verbatim) — the audit row
    // records the delivered action. Absent cap = uncapped.
    const verdict = entry.cap !== undefined && SEVERITY[parsed.action] > SEVERITY[entry.cap]
      ? { ...parsed, action: entry.cap }
      : parsed
    const capped = raw.length > MAX_RAW_CHARS ? `${raw.slice(0, MAX_RAW_CHARS)}…` : raw
    onReview('ok', {
      action: verdict.action,
      reason: verdict.reason,
      response: capped,
      durationMs,
      ...(verdict.confidence !== undefined ? { confidence: verdict.confidence } : {}),
    })
    return { ...verdict, raw: capped }
  }
}

/** Resolve which model would serve the review, from the config + resolved
 * session route. `custom` mode reports the configured endpoint; `session`
 * mode reports the harness route when resolvable. Absent → `undefined`. */
function providerOf(config: ModelReviewPrefs, route?: SessionRoute | undefined): ModelReviewProvider | undefined {
  if (config.mode === 'custom') {
    const baseUrl = config.baseUrl.trim()
    const model = config.model.trim()
    if (baseUrl.length === 0 && model.length === 0) return undefined
    return {
      mode: 'custom',
      ...(baseUrl.length > 0 ? { baseUrl } : {}),
      ...(model.length > 0 ? { model } : {}),
    }
  }
  if (route !== undefined && (route.provider !== undefined || route.model !== undefined)) {
    return {
      mode: 'session',
      ...(route.provider !== undefined ? { provider: route.provider } : {}),
      ...(route.model !== undefined ? { model: route.model } : {}),
    }
  }
  return undefined
}

function defaultTruncate(text: string): string {
  return text.length > MAX_PROMPT_CHARS ? text.slice(0, MAX_PROMPT_CHARS) : text
}

/**
 * The shipped parser factory — the swap point for structured output /
 * function-calling / a new schema later. Change this one function and the whole
 * pipeline consumes the new parsing without touching the engine. It returns the
 * composite parser: the JSON audit parser first (the two-dimension audit
 * shape + the legacy single-object shape, so hand-written JSON prompts keep
 * working), then the two-line parser for the three baseline audit prompts.
 */
export function createModelVerdictParser(): ModelVerdictParser {
  return new CompositeModelVerdictParser()
}

/** Verdict severity lives in {@link SEVERITY}, next to the audit parser. */

/**
 * The demo merge policy (pure, replaceable): combine the rule stage's verdict
 * with the model stage's verdict into the final {@link GuardDecision}.
 *
 * Strictest-wins semantics: `block > ask > warn > allow`. The rule verdict is
 * the floor — the model can upgrade it but never relax it — and when the model
 * finds something stricter it takes over (its reason is carried forward):
 *
 *   - rule block → short-circuited in the engine (model never consulted);
 *   - rule ask + model block → block; rule ask + model ask → ask;
 *     rule ask + model warn/allow → ask (rule is the floor);
 *   - rule warn + model ask/block → the stricter one;
 *   - rule allow + model warn/ask/block → the model verdict (upgrade);
 *   - rule null (stage disabled) + model → model verdict;
 *   - both null → allow by default.
 */
export function mergeVerdicts(
  rule: GuardDecision | null,
  model: ModelVerdict | null,
): GuardDecision {
  const modelSeverity = model !== null ? SEVERITY[model.action] ?? -1 : -1
  const ruleSeverity = rule !== null ? SEVERITY[rule.action] ?? -1 : -1

  if (model !== null && modelSeverity > ruleSeverity) {
    // The model found something stricter than the rule stage did: its verdict
    // (and reason) take over, while the rule's audit trail is preserved.
    const takeover: GuardDecision = {
      action: model.action,
      matchedRules: rule !== null ? rule.matchedRules : [],
      message: model.reason,
      ...(rule !== null && rule.policyId !== undefined ? { policyId: rule.policyId } : {}),
      ...(rule !== null && rule.monitorDowngraded === true ? { monitorDowngraded: true } : {}),
      source: rule !== null ? 'both' : 'model',
      modelVerdict: model,
    }
    // Per-policy monitor mode: the rule stage already downgraded this policy's
    // action to warn, so the model stage cannot re-escalate what the mode gave
    // back — monitor mode never denies.
    if (rule !== null && rule.monitorDowngraded === true
      && (model.action === 'block' || model.action === 'ask')) {
      return { ...takeover, action: 'warn', monitorDowngraded: true }
    }
    return takeover
  }

  if (rule !== null) {
    // The rule verdict is the floor (or ties): the model never relaxes it.
    return { ...rule, source: 'rule' }
  }

  if (model !== null) {
    // Only the model stage ran.
    return {
      action: model.action,
      matchedRules: [],
      message: model.reason,
      source: 'model',
      modelVerdict: model,
    }
  }

  return { action: 'allow', matchedRules: [], message: 'no review stage produced a verdict' }
}

/**
 * The guard pipeline: runs the two pluggable stages in the fixed order
 * `hook → rules → model` and merges into one {@link GuardDecision}. Both
 * stages are independently switchable (`rulesEnabled` + `modelReview.enabled`
 * + per-hook switches); failures fail open.
 */
export class ModelReviewEngine {
  constructor(
    private readonly rules: {
      decide(event: GuardEvent): GuardDecision
      /** Rule-stage switch: a getter function, a plain boolean, or absent (on). */
      rulesEnabled?: (() => boolean) | boolean
      /** Engine-level default mode (`GuardEngine#defaultMode`): when
       * `'monitor'`, the WHOLE pipeline (rules + model) is capped at warn. */
      defaultMode?: (() => GuardMode) | GuardMode
    },
    private readonly model: ModelStage,
  ) {}

  async evaluate(event: GuardEvent, route?: SessionRoute | undefined): Promise<GuardDecision> {
    const rawRulesEnabled = this.rules.rulesEnabled ?? true
    const rulesEnabled = typeof rawRulesEnabled === 'function' ? rawRulesEnabled() : rawRulesEnabled
    const ruleDecision = rulesEnabled ? this.rules.decide(event) : null

    // Short-circuit: `block` is the strictest verdict, so the model could
    // never be stricter — skip the call entirely (saves tokens + latency).
    if (ruleDecision !== null && ruleDecision.action === 'block') {
      return { ...ruleDecision, source: 'rule' }
    }

    let modelVerdict: ModelVerdict | null = null
    if (this.model.enabled()) {
      try {
        modelVerdict = await this.model.evaluate(event, ruleDecision, route)
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error)
        console?.warn?.(`${PREFIX} model stage threw, falling back to rule verdict: ${detail}`)
        modelVerdict = null
      }
    }

    const merged = mergeVerdicts(ruleDecision, modelVerdict)
    // Engine-level monitor mode caps the whole pipeline at warn: a model
    // escalation must not re-create a deny the mode promised never to do
    // (the per-policy variant is already handled inside `mergeVerdicts`).
    const rawMode = this.rules.defaultMode
    const effectiveMode = typeof rawMode === 'function' ? rawMode() : rawMode
    if (effectiveMode === 'monitor' && (merged.action === 'block' || merged.action === 'ask')) {
      return { ...merged, action: 'warn', monitorDowngraded: true }
    }
    return merged
  }
}
