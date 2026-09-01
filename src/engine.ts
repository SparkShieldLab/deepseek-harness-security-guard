/**
 * The local decision engine. Evaluation is fully synchronous, in-process,
 * and deterministic:
 *
 *   - one event in, one {@link GuardDecision} out;
 *   - for the event's hook type, walk matching policies by descending
 *     priority, skip disabled ones, and return the FIRST policy whose rules
 *     match (any rule matches → policy matches, OR semantics);
 *   - no policy matches → allow by default;
 *   - an engine-level error never escapes into the hook path. It degrades to
 *     fail-open (allow) or fail-closed (block) per `failOpen`.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/engine
 */

import { canonicalHook } from './hooks.ts'
import type {
  GuardMode,
  GuardAction,
  GuardDecision,
  GuardEvent,
  GuardOperator,
  GuardPolicy,
  GuardRule,
} from './types.ts'

/** The verdict returned when nothing matches. */
const DEFAULT_DECISION: GuardDecision = {
  action: 'allow',
  matchedRules: [],
  message: 'no rule matched, allow by default',
}

/** Compile a `*`-wildcard glob into an anchored RegExp (all other regex metacharacters are literal). */
function wildcardToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[|\\{}()[\]^$+?.]/g, String.raw`\$&`)
  return new RegExp(`^${escaped.replaceAll('*', '.*')}$`)
}

/**
 * Whether a hook selector (`'*'`, exact name, or glob) matches an event's hook
 * type. Both sides canonicalize, so legacy v0.1.x selectors (`before_tool_call`)
 * keep matching their native seams (`tools/pre-execute`).
 */
function hooksMatch(selectors: readonly string[] | undefined, eventType: string): boolean {
  if (!selectors || selectors.length === 0) return false
  const canonicalEvent = canonicalHook(eventType)
  return selectors.some((raw) => {
    const selector = canonicalHook(raw)
    if (selector === '*') return true
    if (!selector.includes('*')) return selector === canonicalEvent
    return wildcardToRegExp(selector).test(canonicalEvent)
  })
}

/** Own-property lookup with an explicit `undefined` result (never inherited or prototype members). */
function own(record: Record<string, unknown>, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(record, key) ? record[key] : undefined
}

/**
 * Deterministic JSON of the whole event (keys sorted deep) so `raw` rules
 * can match against the original hook payload regardless of insertion order.
 */
function rawEventJson(event: GuardEvent): string {
  return JSON.stringify(sortKeys(event))
}

/** Depth cap for the raw-event key sort; deeper nesting resolves to a sentinel. */
const MAX_SORT_DEPTH = 512

function sortKeys(value: unknown, depth = 0): unknown {
  if (depth >= MAX_SORT_DEPTH) {
    // A model-generated, fully JSON-serializable tool argument can nest many
    // thousand levels; unbounded recursion here would throw and degrade the
    // verdict to fail-open. Return a sentinel instead so the raw rule simply
    // does not match (S9).
    return '[depth-limit-exceeded]'
  }
  if (Array.isArray(value)) return value.map((v) => sortKeys(v, depth + 1))
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortKeys((value as Record<string, unknown>)[key], depth + 1)
    }
    return out
  }
  return value
}

/** Resolve a rule's field against an event (built-ins first, then data, then context). */
function getFieldValue(field: string, event: GuardEvent): unknown {
  switch (field) {
    case 'eventType': return event.eventType
    case 'agentId': return event.agentId
    case 'agentType': return event.agentType
    case 'content': return event.content
    case 'raw': return rawEventJson(event)
    default: {
      const fromData = own(event.data, field)
      if (fromData !== undefined) return fromData
      return own(event.context, field)
    }
  }
}

/** Evaluate one operator. `actual`/`expected` are compared strictly, except the string operators coerce nothing. */
function matchOperator(operator: GuardOperator, actual: unknown, expected: unknown): boolean {
  switch (operator) {
    case 'eq':
      return actual === expected
    case 'neq':
      return actual !== expected
    case 'contains':
      return typeof actual === 'string'
        && typeof expected === 'string'
        && expected.length > 0
        && actual.includes(expected)
    case 'in':
      return Array.isArray(expected) && expected.includes(actual)
    case 'matches':
      return typeof actual === 'string'
        && typeof expected === 'string'
        && wildcardToRegExp(expected).test(actual)
    case 'regex':
      return typeof actual === 'string'
        && typeof expected === 'string'
        && regexMatches(expected, actual)
    default:
      return false
  }
}

/**
 * Evaluate a `regex` operator pattern against a string. Accepts a bare
 * pattern (`^rm\s+`) or the `/pattern/flags` literal form (`/rm/i`). Invalid
 * patterns never match. The guard must fail safe (fail-open by default).
 *
 * ReDoS hardening (S1): patterns with nested/ambiguous quantifiers
 * (`^(a+)+$`, `((a+)|(b+))+`) are rejected as non-matching rather than run
 * against the input, and the input length handed to any user regex is
 * capped. This keeps a synchronous single-threaded `decide()` from freezing
 * the harness event loop (a 22-minute block was measured in review with
 * `^(a+)+$` on 39 chars).
 */
const MAX_REGEX_INPUT = 8_192

/** Catastrophic-backtracking shapes: a quantified group re-quantified, `(a+)+`. */
const RE_NESTED_QUANTIFIER = /\([^()]*[+*][^()]*\)[+*]/
/** Ambiguous alternation inside a quantified group: `(a|aa)+`. */
const RE_AMBIGUOUS_ALTERNATION_QUANTIFIED = /\([^)]*\|[^)]*\)[+*]/
/** A group that already contains a quantifier/alternation re-quantified with a
 * fixed/range repetition `{n}`, `{n,m}` or `{n,}`. `(a?){40}` backtracks
 * exponentially over non-matching input. Plain groups (`(ab){40}`) are linear
 * and deliberately not flagged. */
const RE_AMBIGUOUS_GROUP_REPEATED = /\([^()]*[?+*][^()]*\)\{[0-9]+(?:,[0-9]*)?\}/
/** A group containing an alternation re-quantified with `{n}` repetition. */
const RE_ALTERNATION_GROUP_REPEATED = /\([^)]*\|[^)]*\)\{[0-9]+(?:,[0-9]*)?\}/

/**
 * Neutralize character-class bodies and escape sequences for the regex-based
 * heuristics below, so `[+*?]`, `[a|b]` or `\?` never look like quantifiers
 * or alternations. `[`/`]` frames are preserved for bracket structure; class
 * contents and escapes become `.` (a class-exclusion char that matches none
 * of `[+*?()|]`). The nesting scanner (`hasNestedQuantifiedGroup`) is already
 * class/escape-aware and runs on the RAW pattern.
 */
function neutralizeCharClasses(pattern: string): string {
  let out = ''
  let inClass = false
  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i]
    if (ch === '\\') {
      out += '.'
      i += 1
      continue
    }
    if (inClass) {
      out += '.'
      if (ch === ']') inClass = false
      continue
    }
    if (ch === '[') {
      inClass = true
      out += '['
      continue
    }
    out += ch
  }
  return out
}

/**
 * Whether a group's content carries a `?+*` quantifier at any nesting depth.
 * Character classes, escapes and group modifiers (`?:`, `(?=`, `(?!`, `(?*`,
 * `(?>` — the `?` right after `(`) are skipped so `[+*?]` or `(?:...)` never
 * count as quantifiers. `a{1,2}` (bounded repetition) is deliberately NOT
 * counted: it cannot drive exponential backtracking.
 */
function groupContentHasQuantifier(content: string): boolean {
  let depth = 0
  let inClass = false
  for (let i = 0; i < content.length; i += 1) {
    const ch = content[i]
    if (ch === '\\') {
      i += 1
      continue
    }
    // The group's own modifier (`(?:a)+`, `(?=a)+`) — the `?` right after the
    // enclosing `(`. Only valid as the FIRST char of the content.
    if (i === 0 && ch === '?' && content.length > 1) {
      const modifier = content[1]
      if (modifier === ':' || modifier === '=' || modifier === '!' || modifier === '*' || modifier === '>') {
        i += 1
        continue
      }
    }
    if (inClass) {
      if (ch === ']') inClass = false
      continue
    }
    if (ch === '[') {
      inClass = true
      continue
    }
    if (ch === '(') {
      depth += 1
      // A `?` immediately after `(` is a group modifier, not a quantifier.
      const next = content[i + 1]
      if (next === '?' && content[i + 2] !== undefined) {
        const modifier = content[i + 2]
        if (modifier === ':' || modifier === '=' || modifier === '!' || modifier === '*' || modifier === '>') {
          i += 2
        }
      }
      continue
    }
    if (ch === ')') {
      depth -= 1
      continue
    }
    if (ch === '?' || ch === '+' || ch === '*') return true
  }
  return false
}

/**
 * A quantified group whose content contains a `?+*` quantifier at any depth,
 * e.g. `((a+)|(b+))+`, `((a*)(b?))+`, `(a+(b?))+`, `(?:a+)+`. This is the
 * nested-alternation bomb family — exponential backtracking over non-matching
 * input (`((a+)|(b+))+$` froze the harness for 10s+ on 28 chars during
 * review) — and it slips every regex-based heuristic above because `[^()]*`
 * cannot span a nested group. The scanner is deliberately conservative: any
 * re-quantified group that contains a nested quantifier is rejected as
 * non-matching (same fail-safe posture as the existing heuristics; a linear
 * pattern like `(a?b)+` is collateral, consistent with the documented
 * `(foo|bar){1,3}` trade-off).
 */
function hasNestedQuantifiedGroup(pattern: string): boolean {
  let depth = 0
  let inClass = false
  let groupStart = -1
  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i]
    if (ch === '\\') {
      i += 1
      continue
    }
    if (inClass) {
      if (ch === ']') inClass = false
      continue
    }
    if (ch === '[') {
      inClass = true
      continue
    }
    if (ch === '(') {
      if (depth === 0) groupStart = i
      depth += 1
      continue
    }
    if (ch === ')') {
      depth -= 1
      if (depth === 0 && groupStart !== -1) {
        const content = pattern.slice(groupStart + 1, i)
        let k = i + 1
        while (k < pattern.length && pattern[k] === '?') k += 1 // lazy/possessive suffix
        const next = pattern[k]
        if ((next === '+' || next === '*' || next === '{') && groupContentHasQuantifier(content)) {
          return true
        }
        groupStart = -1
      }
      continue
    }
  }
  return false
}

function isPotentialReDoS(pattern: string): boolean {
  const neutral = neutralizeCharClasses(pattern)
  if (RE_NESTED_QUANTIFIER.test(neutral)) return true
  if (RE_AMBIGUOUS_ALTERNATION_QUANTIFIED.test(neutral)) return true
  if (RE_AMBIGUOUS_GROUP_REPEATED.test(neutral)) return true
  if (RE_ALTERNATION_GROUP_REPEATED.test(neutral)) return true
  if (hasNestedQuantifiedGroup(pattern)) return true
  return false
}

function regexMatches(pattern: string, actual: string): boolean {
  if (actual.length > MAX_REGEX_INPUT) return false
  let source = pattern
  let flags = ''
  const literal = /^\/(.*)\/([a-z]*)$/s.exec(pattern)
  if (literal) {
    source = literal[1] ?? pattern
    flags = literal[2] ?? ''
  }
  if (isPotentialReDoS(source)) return false
  try {
    return new RegExp(source, flags).test(actual)
  } catch {
    return false
  }
}

/** Whether a single rule matches. A missing/unresolvable field never matches. */
function ruleMatches(rule: GuardRule, event: GuardEvent): boolean {
  const actual = getFieldValue(rule.field, event)
  if (actual === undefined || actual === null) return false
  return matchOperator(rule.operator, actual, rule.value)
}

/** OR semantics: a policy matches when ANY of its rules matches. */
function policyMatches(policy: GuardPolicy, event: GuardEvent): boolean {
  return policy.rules.some((rule) => ruleMatches(rule, event))
}

/** Default message rendered when a policy carries none. */
function defaultMessage(action: GuardAction): string {
  switch (action) {
    case 'block': return 'blocked by security guard'
    case 'ask': return 'requires approval by security guard'
    case 'warn': return 'flagged by security guard'
    default: return ''
  }
}

/** In monitor mode, block/ask downgrade to warn; allow/warn stay. */
function downgradeAction(action: GuardAction): GuardAction {
  switch (action) {
    case 'block':
    case 'ask':
      return 'warn'
    default:
      return action
  }
}

/** Ids of every rule that matched (for audit trails). */
function matchedRuleIds(policy: GuardPolicy, event: GuardEvent): string[] {
  return policy.rules
    .filter((rule) => ruleMatches(rule, event))
    .map((rule) => rule.id ?? `${policy.id}.rule`)
}

/** Copy of a policy with its `hooks` selectors canonicalized to native seam names. */
function normalizePolicyHooks(policy: GuardPolicy): GuardPolicy {
  if (!Array.isArray(policy.hooks)) return policy
  const hooks = policy.hooks.map(canonicalHook)
  const unchanged = hooks.every((hook, i) => hook === policy.hooks?.[i])
  return unchanged ? policy : { ...policy, hooks }
}

/**
 * The local decision engine. Constructed once per plugin load from the resolved
 * policies; the policy table can later be swapped atomically via `setPolicies`
 * (UI online config), which bumps `version`. Evaluation stays synchronous and
 * safe to call from any hook listener. Loaded tables are canonicalized, so
 * legacy hook selectors keep matching without a per-event translation cost.
 */
export class GuardEngine {
  private policies: readonly GuardPolicy[]
  private readonly failOpen: boolean
  /** Master switch (user preference); when off, every event is allowed by default. */
  private _enabled = true
  /** Rule-stage switch (pluggable stage #1): when off, the rule engine is
   * bypassed but the model stage still runs. Independent of `_enabled`. */
  private _rulesEnabled = true
  /** Bumped on every swap; 0 = the constructor table untouched. */
  private _version = 0

  constructor(
    policies: readonly GuardPolicy[] = [],
    failOpen = true,
    private readonly _defaultMode: GuardMode = 'protect',
  ) {
    this.policies = policies.map(normalizePolicyHooks)
    this.failOpen = failOpen
  }

  /** Engine-level default mode (individual policies override via their `mode`).
   * The model-review pipeline reads this to cap its merged verdict too. */
  get defaultMode(): GuardMode {
    return this._defaultMode
  }

  /** Monotonic swap counter (0 = initial table). */
  get version(): number {
    return this._version
  }

  /** Whether the engine applies policies. `false` short-circuits every decision to allow. */
  get enabled(): boolean {
    return this._enabled
  }

  /** Set the master switch (the settings preference sync calls this live). */
  setEnabled(enabled: boolean): void {
    this._enabled = enabled
  }

  /** Whether the rule stage is active (pluggable stage #1, settings preference). */
  get rulesEnabled(): boolean {
    return this._rulesEnabled
  }

  /** Set the rule-stage switch (the settings preference sync calls this live). */
  setRulesEnabled(enabled: boolean): void {
    this._rulesEnabled = enabled
  }

  /**
   * Atomically swap the policy table (UI online config, see `policy-store.ts`).
   * Safe under the single-threaded event loop: `decide` reads the reference
   * once per call and never iterates across calls.
   */
  setPolicies(policies: readonly GuardPolicy[]): void {
    this.policies = policies.map(normalizePolicyHooks)
    this._version += 1
  }

  /** Evaluate one event and return a verdict. Never throws. */
  decide(event: GuardEvent): GuardDecision {
    try {
      if (!this._enabled) {
        return { ...DEFAULT_DECISION, message: 'guard disabled, allow by default' }
      }
      if (!this._rulesEnabled) {
        return { ...DEFAULT_DECISION, message: 'rule stage disabled, allow by default' }
      }
      const applicable = this.policies
        .filter((policy) => policy.enabled !== false)
        .filter((policy) => hooksMatch(policy.hooks, event.eventType))
        .sort((a, b) => (b.priority ?? 100) - (a.priority ?? 100))

      for (const policy of applicable) {
        if (policyMatches(policy, event)) {
          const mode = policy.mode ?? this._defaultMode
          const action = mode === 'monitor' ? downgradeAction(policy.action) : policy.action
          return {
            action,
            matchedRules: [policy.id, ...matchedRuleIds(policy, event)],
            message: policy.message ?? defaultMessage(action),
            policyId: policy.id,
            ...(action !== policy.action ? { monitorDowngraded: true } : {}),
          }
        }
      }

      return { ...DEFAULT_DECISION }
    } catch (error) {
      // The engine is the outermost safety boundary: it must never throw into
      // the hook path. Degrade to fail-open/closed per config.
      const message = `guard engine error, ${this.failOpen ? 'allow' : 'block'} by default: ${errorMessage(error)}`
      return {
        action: this.failOpen ? 'allow' : 'block',
        matchedRules: [],
        message,
      }
    }
  }
}

/** Total error message extraction that cannot itself throw on hostile values. */
function errorMessage(error: unknown): string {
  try {
    if (error instanceof Error) return error.message
    if (typeof error === 'object' && error !== null && 'message' in error
      && typeof (error as { message: unknown }).message === 'string') {
      return (error as { message: string }).message
    }
    return String(error)
  } catch {
    return '<unprintable thrown value>'
  }
}
