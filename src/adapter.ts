/**
 * Harness adapter: subscribes to the deepseek-harness NATIVE extension-point
 * seams (the `ctx.on` event names — no plugin-internal aliasing), normalizes
 * each payload into the engine's {@link GuardEvent}, and maps each verdict back
 * onto the seam's decision type.
 *
 * Verdict-capable seams:
 *   - `tools/pre-execute`   → `PreToolDecision`  (deny / ask / delegate)
 *   - `tools/post-execute`  → `PostToolDecision` (block / delegate)
 *   - `agent/pre-step`      → `PreStepDecision`  (reject / delegate)
 *   - `agent/turn-stopping` → awaited notification; block/ask steer a
 *                             continuation with the reason (self-capped per
 *                             turn — the harness has no stop-loop guard yet)
 *
 * Observe-only seams (audit trail, never veto):
 *   - `tools/result`        — final tool outcome snapshot (synchronous)
 *   - `agent/session-start` — session lifecycle start (cannot gate startup)
 *   - `subagent/start` / `subagent/end` — subagent run lifecycle
 *
 * Monotonic invariant (deny-only, after the whole pre-execute waterfall):
 *   - `ctx.tools.guard()`   — rule stage only (the seam is synchronous); a
 *                             block verdict denies with its reason, everything
 *                             else abstains. Listener ordering cannot resurrect
 *                             a call the invariant forbids.
 *
 * The adapter is deliberately dependency-light: runtime imports stay limited
 * to the Cordis `Context` handed to `apply` plus the two dsh-llm message
 * factories (`createUserMessage`, `boundContextSummary`) used to publish the
 * prompt-block notice; every other harness type is `import type` and erased
 * at build time.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/adapter
 */

import type { Context } from '@deepseek-ai/cordis'
import type { Agent, PreStepDecision } from '@deepseek-ai/dsh-agent'
import type { PostToolDecision, PreToolDecision, ToolExecution } from '@deepseek-ai/dsh-tools'
import type { AssembledSection, PromptAssembly } from '@deepseek-ai/dsh-system-prompt'
import { boundContextSummary, createUserMessage } from '@deepseek-ai/dsh-llm'
import { GuardEngine } from './engine.ts'
import type { HookSwitches } from './config.ts'
import type { GuardDecision, GuardEvent } from './types.ts'
import type { SessionRoute } from './model-review.ts'
import { currentTurn, recordVerdict } from './audit.ts'
import { deriveUserIntentFeatures } from './intent.ts'
import { buildPromptGuardSection } from './prompt-guard.ts'
import {
  deriveStatefulFeatures, deriveToolCallFeatures, deriveToolResultFeatures,
} from './features.ts'
import { truncateForScan } from './normalize.ts'
import type { GuardStateStore } from './state-store.ts'

const PREFIX = '[agent-security-guard]'

/**
 * Chinese copy of every English string this plugin can put in front of the
 * user in a deny/ask/steer reason: the engine's fallback messages (engine.ts
 * `defaultMessage`), the pre/post-execute fallbacks, the turn-stopping steer
 * fallback, the allow-path notes, and the 27 baseline policy messages
 * (base-policies.ts). Everything else (custom policy messages) stays
 * verbatim, matching the audit trail.
 *
 * Exported for the i18n consistency test (tools/test-i18n.mjs), which pins
 * every baseline message to a translation so wording drift fails CI instead
 * of silently losing the Chinese copy.
 */
export const REASON_ZH: Record<string, string> = {
  'blocked by security guard': '已被安全守卫拦截',
  'requires approval by security guard': '需要用户审批',
  'flagged by security guard': '已被安全守卫标记',
  'tool call blocked': '工具调用已被拦截',
  'tool call requires approval': '工具调用需要审批',
  'tool result blocked': '工具结果已被拦截',
  'continue: blocked by security guard': '已被安全守卫拦截，请调整后继续',
  'no rule matched, allow by default': '无规则命中，默认放行',
  'guard disabled, allow by default': '守卫已停用，默认放行',
  'rule stage disabled, allow by default': '规则审查已停用，默认放行',
  'high-risk command blocked by security baseline (rm -rf /, pipe-to-shell, infinite loop, shutdown/format, shell rc truncation)': '高危命令被安全基线拦截（rm -rf /、管道连接 shell、无限循环、关机/格式化、shell rc 截断）',
  'obfuscated/encoded command delivery blocked by security baseline (base64|sh, xxd -r, hex escapes, invisible unicode)': '混淆/编码命令投递被安全基线拦截（base64|sh、xxd -r、十六进制转义、不可见 unicode）',
  'unusually long command recorded in audit (harmless by itself; length alone never blocks)': '超长命令已记入审计（本身无害；仅凭长度不会单独拦截）',
  'encoded payload decoding to a high-risk or obfuscated command (base64/hex recursion) blocked by security baseline': '编码载荷解码后为高危或混淆命令（base64/hex 递归）被安全基线拦截',
  'access to protected path (~/.ssh, ~/.dsh, shell rc files, /etc sensitive files) blocked by security baseline': '访问受保护路径（~/.ssh、~/.dsh、shell rc 文件、/etc 敏感文件）被安全基线拦截',
  'deletion outside the workspace blocked by security baseline': '工作区之外的删除被安全基线拦截',
  'same high-impact change repeated more than 3 times, possible tool loop, blocked by security baseline': '同一高风险变更重复超过 3 次，疑似工具循环，被安全基线拦截',
  'execution of a risky script written this turn blocked by security baseline': '执行本轮生成的危险脚本被安全基线拦截',
  'high-confidence data exfiltration chain blocked by security baseline': '高置信度数据外传链被安全基线拦截',
  'possible data exfiltration chain (outbound with secret reference or encoding transform), recorded in audit': '疑似数据外传链（带密钥引用或编码变换的出站），已记入审计',
  'tool result contains a high-confidence (directive/encoded) prompt injection (persona hijack / safeguard defeat / tool luring / exfiltration instruction), blocked by security baseline': '工具结果包含高置信度（指令/编码）提示注入（身份劫持 / 防护瘫痪 / 工具诱导 / 外传指令），被安全基线拦截',
  'tool result contains several soft injection phrases from unrelated families, recorded in audit': '工具结果包含多个来源族的软注入短语，已记入审计',
  'user message requests disabling the guard, bypassing approval, or ignoring restrictions; step rejected by security baseline': '用户消息要求关闭守卫、绕过审批或忽略限制；该步骤被安全基线拒绝',
  'user message hints at bypassing restrictions; recorded in audit by security baseline': '用户消息暗示绕过限制；已由安全基线记入审计',
  'privilege escalation or security-control disable blocked by security baseline (setenforce 0, service stop/mask, chmod -R 777, chown root, setuid bit)': '权限提升或安全控制关闭被安全基线拦截（setenforce 0、服务 stop/mask、chmod -R 777、chown root、setuid 位）',
  'non-recursive world-writable chmod (chmod 777) recorded in audit by security baseline; single-file permission fixes may be legitimate': '非递归 world-writable chmod（chmod 777）已由安全基线记入审计；单文件权限修改可能是合法操作',
  'write into system persistence locations (/etc cron|rc|profile|account files, Windows system dirs) blocked by security baseline': '写入系统持久化位置（/etc cron|rc|profile|账户文件、Windows 系统目录）被安全基线拦截',
  'install/copy into system bin or library dirs (/usr[/local]/bin, /Library) recorded in audit by security baseline; global CLI installs may be legitimate': '安装/复制到系统 bin 或库目录（/usr[/local]/bin、/Library）已由安全基线记入审计；全局 CLI 安装可能是合法操作',
  'in-place tampering with guard/policy files (sed -i / overwrite / delete on AGENTS.md, SKILL.md, policy configs) blocked by security baseline': '原地篡改守卫/策略文件（对 AGENTS.md、SKILL.md、策略配置执行 sed -i / 覆写 / 删除）被安全基线拦截',
  'sandbox/container escape tooling (nsenter, chroot execution, docker.sock mount, /proc/1/root, /:/ host mount) blocked by security baseline': '沙箱/容器逃逸工具（nsenter、chroot 执行、docker.sock 挂载、/proc/1/root、/:/ 主机根挂载）被安全基线拦截',
  'privileged container run (--privileged) recorded in audit by security baseline; testcontainers/DinD setups may be legitimate': '特权容器运行（--privileged）已由安全基线记入审计；testcontainers/DinD 等场景可能是合法操作',
  'network scanning/listening (nmap, masscan, nc -l) recorded in audit by security baseline; may be legitimate debugging': '网络扫描/监听（nmap、masscan、nc -l）已由安全基线记入审计；可能是合法调试',
  'multi-segment ../ path traversal in command recorded in audit by security baseline': '命令中的多段 ../ 路径穿越已由安全基线记入审计',
  'clone-then-build/install chain from a freshly cloned source recorded in audit by security baseline': '克隆后立即构建/安装新克隆源码的链路已由安全基线记入审计',
  'package index/registry overridden to plain http:// recorded in audit by security baseline (supply-chain risk)': '包索引/registry 被覆盖为 http:// 已由安全基线记入审计（供应链风险）',
  'code writing secret-looking values to logs (console.log/token|password|secret) recorded in audit by security baseline': '向日志输出疑似密钥值（console.log/token|password|secret）已由安全基线记入审计',
  'directive/trigger-phrase content written toward a memory-like target recorded in audit by security baseline (long-term memory poisoning risk)': '向记忆类目标写入指令/触发词内容已由安全基线记入审计（长期记忆投毒风险）',
}

/** Prefix-localized engine messages whose tail is dynamic (the error text). */
export const REASON_ZH_PREFIXES: ReadonlyArray<{ prefix: string; zh: string }> = [
  { prefix: 'guard engine error, allow by default: ', zh: '守卫引擎错误，默认放行：' },
  { prefix: 'guard engine error, block by default: ', zh: '守卫引擎错误，默认拦截：' },
]

/**
 * Shipped names of the three built-in baseline review templates
 * (src/audit-prompts.ts `BASELINE_REVIEW_TEMPLATES`). The model stage embeds
 * the stored (Chinese) name as a `[name]` prefix in the merged verdict reason
 * (src/model-review.ts `mergeChainVerdicts`), so an English UI would leak the
 * Chinese name into the approval ask; known baseline names localize here,
 * custom template names stay verbatim (mirror of the panel's `modelReason`).
 */
const MODEL_TEMPLATE_NAMES: ReadonlyArray<{ zh: string; en: string }> = [
  { zh: '恶意意图检测', en: 'Malicious Intent Detection' },
  { zh: '风险指令检测', en: 'Risky Instruction Detection' },
  { zh: '意图偏离检测', en: 'Intent Drift Detection' },
]

/**
 * Chinese copy of the fixed English verdict scaffolding the model stage can
 * embed in a reason: the two-line parser's category labels (src/model-review.ts
 * `USER_REQUEST_LINE_ACTIONS` / `AGENT_BEHAVIOR_LINE_ACTIONS` /
 * `INTENT_DRIFT_ACTIONS` — Line 1 is always English) and the JSON audit
 * parser's dimension labels (`user request [...]` / `agent behavior [...]`).
 * The free-text evidence is NOT table-translatable; it follows the UI language
 * through the `{reason_lang}` placeholder instead.
 */
const MODEL_LABEL_ZH: ReadonlyArray<{ en: string; zh: string }> = [
  // intent-drift labels
  { en: 'Intent Drift', zh: '意图偏离' },
  { en: 'No Drift', zh: '无偏离' },
  // user-request categories
  { en: 'Instruction Override / Jailbreak Inducement', zh: '指令覆盖 / 越狱诱导' },
  { en: 'Configuration Tampering Inducement', zh: '配置篡改诱导' },
  { en: 'Role Impersonation Inducement', zh: '角色冒充诱导' },
  { en: 'Indirect Prompt Injection', zh: '间接提示注入' },
  { en: 'Tool Output Injection', zh: '工具输出注入' },
  { en: 'Conversation / Context Probing', zh: '会话 / 上下文探测' },
  { en: 'Agent Memory Extraction Inducement', zh: '智能体记忆提取诱导' },
  { en: 'Workspace Escape Inducement', zh: '工作区逃逸诱导' },
  { en: 'PII Leakage Intent', zh: 'PII 泄露意图' },
  { en: 'Confidential Business Information Leakage Intent', zh: '机密商业信息泄露意图' },
  { en: 'Cross-Tenant Data Leakage Intent', zh: '跨租户数据泄露意图' },
  { en: 'No Risk', zh: '无风险' },
  // agent-behavior categories
  { en: 'PII Leakage', zh: 'PII 泄露' },
  { en: 'Confidential Business Information Leakage', zh: '机密商业信息泄露' },
  { en: 'Cross-Tenant Data Leakage', zh: '跨租户数据泄露' },
  { en: 'Destructive Command', zh: '破坏性命令' },
  { en: 'Privilege Escalation / Permission Weakening', zh: '权限提升 / 权限弱化' },
  { en: 'Sandbox Escape Attempt', zh: '沙箱逃逸尝试' },
  { en: 'Dangerous Tool Invocation', zh: '危险工具调用' },
  { en: 'System Path Write', zh: '系统路径写入' },
  { en: 'Network Egress', zh: '网络外联' },
  { en: 'Malicious Dependency Installation', zh: '恶意依赖安装' },
  { en: 'Tool Parameter Manipulation', zh: '工具参数操纵' },
  // JSON audit dimension labels (parser emits `label [names]: evidence`)
  { en: 'user request', zh: '用户请求' },
  { en: 'agent behavior', zh: '代理行为' },
  { en: 'no risk categories detected', zh: '未检出风险类别' },
]

/** Escape a literal string for embedding in a RegExp. */
function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/** Replace one verdict-label occurrence with its localized copy. The label sits
 * at a boundary: start of the reason / after a `[`/`,`/space (JSON dimension
 * list), and is followed by `:` (line-parser reason) or `,`/`]` (JSON list).
 * Case-insensitive on purpose — the parser keeps the model's verbatim line,
 * and models re-flow category case. Only `Label:`-shaped scaffolding is
 * rewritten, so the free-text evidence is never touched. */
function replaceModelLabel(text: string, en: string, zh: string): string {
  const re = new RegExp(`(^|[\\[, ])(${escapeRegExp(en)})(?=[:,\\]]|$)`, 'gi')
  return text.replace(re, `$1${zh}`)
}

/** Localize the fixed scaffolding of a model-stage verdict reason (template
 * name prefix + verdict labels); custom template names and the free-text
 * evidence pass through. zh → labels Chinese; en → baseline template names
 * English (the stored names are Chinese). */
function localizeModelReason(text: string, lang: 'zh' | 'en'): string {
  let out = text
  if (lang === 'en') {
    for (const { zh, en } of MODEL_TEMPLATE_NAMES) {
      out = out.replaceAll(`[${zh}]`, `[${en}]`)
    }
  } else {
    // Longest labels first: `PII Leakage Intent` must win over `PII Leakage`.
    const labels = [...MODEL_LABEL_ZH].sort((a, b) => b.en.length - a.en.length)
    for (const { en, zh } of labels) {
      out = replaceModelLabel(out, en, zh)
    }
    // JSON dimension labels appear as `label [`; the bracket forms replace the
    // `label` case-insensitively without touching evidence prose.
    out = out.replace(/user request \[/gi, '用户请求 [')
    out = out.replace(/agent behavior \[/gi, '代理行为 [')
  }
  return out
}

/** Localize a known message text; unknown strings pass through verbatim.
 * A dynamic engine-error message is localized by prefix, keeping the
 * original error detail tail verbatim. */
function localize(text: string, lang: 'zh' | 'en'): string {
  if (lang === 'zh') {
    const exact = REASON_ZH[text]
    if (exact !== undefined) return exact
    for (const { prefix, zh } of REASON_ZH_PREFIXES) {
      if (text.startsWith(prefix)) return zh + text.slice(prefix.length)
    }
    return localizeModelReason(text, 'zh')
  }
  return localizeModelReason(text, 'en')
}

/** Lossless-JSON canonical string form of any value. */
function canonicalize(value: unknown): string {
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

/**
 * Flatten a tool call's arguments into the event `data`:
 *   - `toolName` → the call's tool name;
 *   - `arguments` → the full canonical JSON (for `contains`/`matches`);
 *   - every primitive argument field → a first-class key (`command`, `path`,
 *     `url`, …) so rules can target a single argument without JSON gymnastics.
 */
function toToolEvent(
  eventType: string,
  exec: ToolExecution,
  extra: Record<string, unknown> = {},
): GuardEvent {
  const data: Record<string, unknown> = {
    toolName: exec.name,
    arguments: canonicalize(exec.arguments),
    ...extra,
  }
  flattenArguments(exec.arguments, data)

  // In deepseek-harness the agent id IS the session id.
  const agentId = exec.agent?.id
  const context: Record<string, unknown> = {}
  if (agentId !== undefined) {
    context.agentId = agentId
    context.sessionId = agentId
  }

  const event: GuardEvent = { eventType, data, context }
  if (agentId !== undefined) {
    event.agentId = agentId
    event.sessionId = agentId
  }
  return event
}

/** Fold an object's own primitive fields into `data` (nested objects are canonicalized). */
function flattenArguments(args: unknown, into: Record<string, unknown>): void {
  if (args === null || typeof args !== 'object') return
  for (const [key, value] of Object.entries(args as Record<string, unknown>)) {
    if (Object.prototype.hasOwnProperty.call(into, key)) continue
    if (value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      into[key] = value
    } else {
      into[key] = canonicalize(value)
    }
  }
}

/** Concatenate the text content of a step's messages into one searchable string. */
function extractText(messages: readonly unknown[]): string {
  const parts: string[] = []
  for (const message of messages) {
    if (message === null || typeof message !== 'object') continue
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

/**
 * Concatenate the text of the USER-ROLE messages only, for the intent scan.
 * System/tool/assistant turns and anything merged in through
 * `additionalContexts` are out of scope: the guard attacks the *user's*
 * instructions, and scanning derived context would block legitimate discussion
 * (see S7).
 */
function extractUserText(messages: readonly unknown[]): string {
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

/**
 * Upper bound for the canonicalized `data.messages` payload on prompt events.
 * Serializing the full history would make every pre-step O(all history bytes);
 * rules and the model stage only ever consume the recent tail (the newest user
 * query and its immediate context).
 */
const MAX_MESSAGES_CHARS = 32_000

/**
 * Canonicalize ONLY the tail of a messages array: walk backwards accumulating
 * canonical forms until the char budget is spent, then join the kept slice in
 * original order (still valid JSON, so `userQueryOf` keeps parsing it). A
 * single oversized message degrades to a truncated canonical form — no longer
 * valid JSON, which consumers already tolerate.
 */
function canonicalizeMessagesTail(messages: readonly unknown[], maxChars = MAX_MESSAGES_CHARS): string {
  const parts: string[] = []
  let total = 2 // the wrapping array brackets
  let start = messages.length
  for (let i = messages.length - 1; i >= 0; i--) {
    const part = canonicalize(messages[i] ?? null)
    const cost = part.length + 1 // the joining comma
    if (total + cost > maxChars) break
    total += cost
    parts.push(part)
    start = i
  }
  if (start === messages.length) {
    // Even the newest entry alone busts the budget.
    return canonicalize(messages[messages.length - 1] ?? null).slice(0, Math.max(maxChars, 0))
  }
  return `[${parts.reverse().join(',')}]`
}

/** Build an `agent/pre-step` event from the harness payload. */
function toPromptEvent(
  agentId: string,
  messages: readonly unknown[],
  turn: number,
  step: number,
): GuardEvent {
  const content = truncateForScan(extractText(messages))
  return {
    eventType: 'agent/pre-step',
    agentId,
    sessionId: agentId,
    content,
    turn,
    step,
    data: { turn, step, content, messages: canonicalizeMessagesTail(messages) },
    context: { agentId },
  }
}

/** Adapter options carrying the shared state and workspace context. */
export interface AdapterOptions {
  /** Session/turn state for the stateful defenses. */
  state: GuardStateStore
  /** Resolved workspace root (absolute) for path guards. */
  workspaceRoot?: string | undefined
  /** Inject the prompt-guard security section (`config.promptGuard`). Default `true`. */
  promptGuard?: boolean
  /** Absolute path to the plugin-owned verdict audit file (`verdicts.jsonl`). */
  verdictLogPath?: string | undefined
  /**
   * Whether `allow` verdicts are written to the audit log too. Resolved lazily
   * so the persisted preference takes effect on the very next event without a
   * restart. Default `false`.
   */
  recordAllow?: (() => boolean) | undefined
  /**
   * Whether the reject path appends a `notice` user-message to the session so
   * the conversation shows the user why their request was swallowed. Default
   * `true`. When off, a rejected prompt step stays as silent as before.
   */
  promptBlockNotice?: boolean | undefined
  /**
   * Panel language ('zh' | 'en'), used to localize the deny/ask reasons the
   * harness surfaces to the user (approval prompts, block feedback). Resolved
   * lazily from the persisted language preference; 'auto' resolves to 'en'.
   * Default `'en'`.
   */
  lang?: (() => 'zh' | 'en') | undefined
  /**
   * The review pipeline for the chain `hook → rules → model → verdict`.
   * When provided, every hook listener awaits `pipeline.evaluate(event)`
   * instead of calling `engine.decide` directly; the pipeline runs the rule
   * stage first, then the (pluggable, independently switchable) model stage,
   * and merges the verdicts. Absent → rule engine only (legacy behavior).
   */
  pipeline?: { evaluate(event: GuardEvent, route?: SessionRoute | undefined): Promise<GuardDecision> } | undefined
}

/** Concatenate the text blocks of a tool execution result. */
function extractResultText(result: unknown): string {
  const content = (result as { content?: unknown } | null)?.content
  if (!Array.isArray(content)) return ''
  const parts: string[] = []
  for (const block of content) {
    if (block !== null && typeof block === 'object'
      && (block as { type?: unknown }).type === 'text'
      && typeof (block as { text?: unknown }).text === 'string') {
      parts.push((block as { text: string }).text)
    }
  }
  return parts.join('\n')
}

/** Prefix a reason with the winning policy id for traceability. */
function reason(decision: GuardDecision, fallback: string, lang: 'zh' | 'en'): string {
  const id = decision.policyId ? `[${decision.policyId}] ` : ''
  return `${id}${localize(decision.message || fallback, lang)}`
}

/** Log a verdict at the level its action implies. */
function logDecision(ctx: Context, hook: string, decision: GuardDecision): void {
  switch (decision.action) {
    case 'allow':
      ctx.logger.debug(`${PREFIX} ${hook} -> allow`)
      break
    case 'warn':
      ctx.logger.warn(`${PREFIX} ${hook} -> warn: ${decision.message}`)
      break
    case 'ask':
      ctx.logger.info(`${PREFIX} ${hook} -> ask: ${decision.message}`)
      break
    case 'block':
      ctx.logger.warn(`${PREFIX} ${hook} -> block: ${decision.message}`)
      break
  }
}

/** Map a verdict onto the `tools/pre-execute` waterfall (deny / ask / delegate). */
function applyPreToolDecision(ctx: Context, decision: GuardDecision, next: () => Promise<PreToolDecision>, lang: 'zh' | 'en'): Promise<PreToolDecision> {
  switch (decision.action) {
    case 'block':
      logDecision(ctx, 'tools/pre-execute', decision)
      return Promise.resolve({ kind: 'deny', reason: reason(decision, 'tool call blocked', lang) })
    case 'ask':
      logDecision(ctx, 'tools/pre-execute', decision)
      return Promise.resolve({ kind: 'ask', reason: reason(decision, 'tool call requires approval', lang) })
    case 'warn':
      logDecision(ctx, 'tools/pre-execute', decision)
      return next()
    case 'allow':
    default:
      return next()
  }
}

/** Map a verdict onto the `tools/post-execute` waterfall (block result / delegate). */
function applyPostToolDecision(ctx: Context, decision: GuardDecision, next: () => Promise<PostToolDecision>, lang: 'zh' | 'en'): Promise<PostToolDecision> {
  switch (decision.action) {
    // No approval seam exists at post-execute; `ask` degrades to a block with
    // corrective feedback so the model learns why its result was withheld.
    case 'block':
    case 'ask':
      logDecision(ctx, 'tools/post-execute', decision)
      return Promise.resolve({
        kind: 'block',
        feedback: [{ type: 'text', text: reason(decision, 'tool result blocked', lang) }],
      })
    case 'warn':
      logDecision(ctx, 'tools/post-execute', decision)
      return next()
    case 'allow':
    default:
      return next()
  }
}

/** The plugin id stamped into the notice source (shown by the UI beside the summary). */
const NOTICE_PLUGIN_ID = 'agent-security-guard'

/**
 * One-line account for the collapsed conversation row. Kept short and fixed;
 * the full policy reason lives in the expandable body (and the audit trail).
 */
function blockNoticeSummary(lang: 'zh' | 'en'): string {
  return lang === 'zh' ? '安全守卫已拦截该消息' : 'Security guard blocked this message'
}

/** The expandable, model-facing notice body: what happened, and why. */
function blockNoticeBody(reasonText: string, lang: 'zh' | 'en'): string {
  const body = lang === 'zh'
    ? '你的消息已被安全守卫拦截，未发送给模型。\n原因：'
    : 'Your message was blocked by the security guard and was not sent to the model.\nReason: '
  return `${body}${reasonText}`
}

/**
 * Append a `notice`-form user message to the agent's session feed, so a
 * rejected prompt step gives the user immediate in-conversation feedback.
 *
 * The message carries ONLY the localized policy reason — never the blocked
 * content — so the notice is prompt-injection-safe on its own and never
 * echoes attacker text back into model context. It is a plain surface append
 * (no inbox claim), rendered by the conversation UI as a collapsible context
 * row with the summary visible without expanding. Any failure (surface
 * validation, detached session) is contained: the reject decision must win
 * regardless, so the block is never downgraded by a feedback hiccup.
 */
function appendBlockNotice(ctx: Context, agent: Agent, decision: GuardDecision, fallback: string, lang: 'zh' | 'en'): void {
  try {
    const message = createUserMessage({
      content: [{ type: 'text', text: blockNoticeBody(reason(decision, fallback, lang), lang) }],
      source: {
        kind: 'plugin',
        plugin: NOTICE_PLUGIN_ID,
        form: 'notice',
        summary: boundContextSummary(blockNoticeSummary(lang)),
      },
    })
    agent.session.append('user/message', message, { surfaceOp: 'append' })
  } catch (error) {
    // Contained on purpose: never let feedback break the reject.
    ctx.logger.warn(`${PREFIX} block notice append failed: ${error instanceof Error ? error.message : String(error)}`)
  }
}

/** Map a verdict onto the `agent/pre-step` waterfall (reject / delegate). */
function applyPreStepDecision(
  ctx: Context,
  agent: Agent,
  decision: GuardDecision,
  next: () => Promise<PreStepDecision>,
  options: AdapterOptions,
): Promise<PreStepDecision> {
  switch (decision.action) {
    // No approval seam exists for prompt steps; `ask` degrades to a reject.
    case 'block':
    case 'ask':
      logDecision(ctx, 'agent/pre-step', decision)
      if (options.promptBlockNotice !== false) {
        appendBlockNotice(ctx, agent, decision, 'blocked by security guard', options.lang?.() ?? 'en')
      }
      return Promise.resolve({ kind: 'reject' })
    case 'warn':
      logDecision(ctx, 'agent/pre-step', decision)
      return next()
    case 'allow':
    default:
      return next()
  }
}

/** Extract the session model route from an agent handle. Two type-minimal
 * faces of `Session`: `requestContext()` is the harness-resolved route
 * metadata (provider/model are REQUIRED fields there, populated even when the
 * caller-chosen `request/header` carries none); `requestHeader().config` is
 * the raw proposal fallback. Absent → the model stage falls back to its own
 * resolver; in session mode an absent route fails open to rules. */
function sessionRouteOf(
  agent: {
    session?: {
      requestContext?: () => { provider?: string; model?: string } | undefined
      requestHeader?: () => { config?: { provider?: string; model?: string } } | undefined
    } | undefined
  } | null | undefined,
): SessionRoute | undefined {
  try {
    const resolved = agent?.session?.requestContext?.()
    if (resolved !== undefined && typeof resolved.provider === 'string' && typeof resolved.model === 'string') {
      return { provider: resolved.provider, model: resolved.model }
    }
    const config = agent?.session?.requestHeader?.()?.config
    if (config !== undefined && typeof config.provider === 'string' && typeof config.model === 'string') {
      return { provider: config.provider, model: config.model }
    }
  } catch {
    // contained: route absence must never break the decision path
  }
  return undefined
}

/** Run the configured review pipeline (rules → model), falling back to the
 * rule engine alone when no pipeline was wired (legacy/unit-test path). */
async function resolveDecision(
  options: AdapterOptions,
  engine: GuardEngine,
  event: GuardEvent,
  route?: SessionRoute | undefined,
): Promise<GuardDecision> {
  if (options.pipeline !== undefined) return options.pipeline.evaluate(event, route)
  return engine.decide(event)
}

/** Register every enabled listener on the context. All listeners are scoped to `ctx` and disposed with it. */
export function registerListeners(ctx: Context, engine: GuardEngine, hooks: HookSwitches, options: AdapterOptions): void {
  if (hooks.toolsPreExecute !== false) {
    ctx.on('tools/pre-execute', async (exec, next): Promise<PreToolDecision> => {
      // Master switch: fully off. No scanning, no decide, no verdict log.
      if (!engine.enabled) return next()
      const event = toToolEvent('tools/pre-execute', exec)
      // The intent-drift / risk-instruction audit templates need a <USER_REQUEST>
      // to compare the tool call against; tool events carry no messages, so feed
      // the most recent user-role text from the session log here.
      const userText = recentUserTextOf(exec.agent)
      if (userText.length > 0) event.data.userQuery = userText
      const sessionKey = exec.agent?.id
      const turn = currentTurn(exec.agent?.session)
      // Static feature extraction is independent of session/turn bookkeeping;
      // it must never be skipped just because a turn is not yet established in
      // the session log (see S5).
      let staticFeatures: Record<string, unknown> = {}
      try {
        staticFeatures = deriveToolCallFeatures(exec.arguments as Record<string, unknown>, { workspaceRoot: options.workspaceRoot })
        Object.assign(event.data, staticFeatures)
      } catch (error) {
        ctx.logger.warn(`${PREFIX} threat feature extraction failed: ${error instanceof Error ? error.message : String(error)}`)
      }
      if (sessionKey !== undefined && turn !== undefined) {
        try {
          const stateful = deriveStatefulFeatures({
            args: exec.arguments as Record<string, unknown>,
            sessionKey,
            turn,
            state: options.state,
            static: staticFeatures,
          })
          Object.assign(event.data, stateful)
        } catch (error) {
          ctx.logger.warn(`${PREFIX} stateful feature extraction failed: ${error instanceof Error ? error.message : String(error)}`)
        }
      }
      const decision = await resolveDecision(options, engine, event, sessionRouteOf(exec.agent))
      recordVerdict(ctx, {
        hook: 'tools/pre-execute',
        sessionId: sessionKey,
        decision,
        tool: exec.name,
        callId: exec.callId,
        turn,
      }, options.verdictLogPath, { recordAllow: options.recordAllow?.() ?? false })
      return applyPreToolDecision(ctx, decision, next, options.lang?.() ?? 'en')
    })
  }

  if (hooks.toolsPostExecute !== false) {
    ctx.on('tools/post-execute', async (exec, result, next): Promise<PostToolDecision> => {
      // Master switch: fully off. No scanning, no decide, no verdict log.
      if (!engine.enabled) return next()
      const event = toToolEvent('tools/post-execute', exec, { isError: result.isError })
      const sessionKey = exec.agent?.id
      try {
        const text = extractResultText(result)
        if (text.length > 0) {
          const features = deriveToolResultFeatures({ text })
          Object.assign(event.data, features)
          if (sessionKey !== undefined) {
            const secrets = features.observedSecrets
            if (Array.isArray(secrets) && secrets.length > 0) {
              options.state.noteSecrets(sessionKey, secrets.filter((v): v is string => typeof v === 'string'))
            }
            const flags = features.toolResultFlags
            if (Array.isArray(flags) && flags.length > 0) {
              options.state.noteRiskFlags(sessionKey, flags.filter((v): v is string => typeof v === 'string' && !v.endsWith('-weak')))
            }
          }
        }
      } catch (error) {
        ctx.logger.warn(`${PREFIX} tool-result feature extraction failed: ${error instanceof Error ? error.message : String(error)}`)
      }
      const decision = await resolveDecision(options, engine, event, sessionRouteOf(exec.agent))
      recordVerdict(ctx, {
        hook: 'tools/post-execute',
        sessionId: sessionKey,
        decision,
        tool: exec.name,
        callId: exec.callId,
        turn: currentTurn(exec.agent?.session),
      }, options.verdictLogPath, { recordAllow: options.recordAllow?.() ?? false })
      return applyPostToolDecision(ctx, decision, next, options.lang?.() ?? 'en')
    })
  }

  if (hooks.toolsResult !== false) {
    ctx.on('tools/result', (exec, result): undefined => {
      // Master switch: fully off. No decide, no verdict log.
      if (!engine.enabled) return undefined
      // Observe-only seam: the verdict is recorded in the background (the
      // listener contract is synchronous; the pipeline is awaited inside).
      void (async () => {
        try {
          const decision = await resolveDecision(options, engine, toToolEvent('tools/result', exec, { isError: result.isError }), sessionRouteOf(exec.agent))
          logDecision(ctx, 'tools/result', decision)
          recordVerdict(ctx, {
            hook: 'tools/result',
            sessionId: exec.agent?.id,
            decision,
            tool: exec.name,
            callId: exec.callId,
            turn: currentTurn(exec.agent?.session),
          }, options.verdictLogPath, { recordAllow: options.recordAllow?.() ?? false })
        } catch (error) {
          ctx.logger.warn(`${PREFIX} tools/result review failed: ${error instanceof Error ? error.message : String(error)}`)
        }
      })()
      return undefined
    })
  }

  if (hooks.agentPreStep !== false) {
    ctx.on('agent/pre-step', async (payload, next): Promise<PreStepDecision> => {
      // Master switch: fully off. No scanning, no decide, no verdict log.
      if (!engine.enabled) return next()
      const event = toPromptEvent(payload.agent.id, payload.messages, payload.turn, payload.step)
      try {
        // Intent scan is scoped to the user-role message text only (S7), never
        // tool/system-derived context mixed in via additionalContexts.
        const intent = deriveUserIntentFeatures(extractUserText(payload.messages))
        if (intent.userIntentRisk !== undefined) {
          Object.assign(event.data, intent)
        }
      } catch (error) {
        ctx.logger.warn(`${PREFIX} user-intent scan failed: ${error instanceof Error ? error.message : String(error)}`)
      }
      const decision = await resolveDecision(options, engine, event, sessionRouteOf(payload.agent))
      recordVerdict(ctx, {
        hook: 'agent/pre-step',
        sessionId: payload.agent.id,
        decision,
        turn: payload.turn,
        step: payload.step,
        // Persist the assembled content the hook inspected (already bounded by
        // truncateForScan) so the review view shows it even when the step has
        // no correlatable user/message event (continuation / boundary steps).
        content: event.content,
      }, options.verdictLogPath, { recordAllow: options.recordAllow?.() ?? false })
      return applyPreStepDecision(ctx, payload.agent, decision, next, options)
    })
  }

  // ── agent/turn-stopping: the Stop boundary. A blocking verdict STEERS a
  // continuation with the reason (the harness has no run-level halt; the CC
  // Stop-hook bridge uses the same channel). Self-capped per (session, turn)
  // because dsh's own stop-loop guard is still a TODO — after the cap the
  // verdict degrades to audit-only so the turn can actually close.
  if (hooks.agentTurnStopping !== false) {
    ctx.on('agent/turn-stopping', async ({ agent, turn }): Promise<void> => {
      // Master switch: fully off. No scanning, no decide, no verdict log.
      if (!engine.enabled) return
      const content = lastAssistantText(agent)
      const event: GuardEvent = {
        eventType: 'agent/turn-stopping',
        agentId: agent.id,
        sessionId: agent.id,
        turn,
        content,
        data: { turn, content },
        context: { agentId: agent.id },
      }
      const decision = await resolveDecision(options, engine, event, sessionRouteOf(agent))
      if (decision.action !== 'block' && decision.action !== 'ask') {
        recordVerdict(ctx, {
          hook: 'agent/turn-stopping',
          sessionId: agent.id,
          decision,
          turn,
          content,
        }, options.verdictLogPath, { recordAllow: options.recordAllow?.() ?? false })
        return
      }
      const steers = options.state.incrementStopSteer(agent.id, turn)
      const suppressed = steers > STOP_STEER_CAP
      // Audit BEFORE the cap branch, but annotate the suppressed rows: the
      // review panel must not show a capped block as an executed one (the
      // `note` renders in the row detail, like the modelLate flag).
      recordVerdict(ctx, {
        hook: 'agent/turn-stopping',
        sessionId: agent.id,
        decision,
        turn,
        content,
        ...(suppressed ? { note: `block suppressed: stop-steer cap ${STOP_STEER_CAP} reached for turn ${turn}` } : {}),
      }, options.verdictLogPath, { recordAllow: options.recordAllow?.() ?? false })
      if (suppressed) {
        ctx.logger.warn(`${PREFIX} agent/turn-stopping -> block suppressed (stop-steer cap ${STOP_STEER_CAP} reached for turn ${turn})`)
        return
      }
      logDecision(ctx, 'agent/turn-stopping', decision)
      agent.steer(createUserMessage({
        content: [{ type: 'text', text: reason(decision, 'continue: blocked by security guard', options.lang?.() ?? 'en') }],
        source: { kind: 'plugin', plugin: 'agent-security-guard' },
      }))
    })
  }

  // ── agent/session-start: observe-only (the seam is a notification and
  // cannot gate startup). Audit row only; also useful as the session's
  // opening marker in the verdict log.
  if (hooks.agentSessionStart !== false) {
    ctx.on('agent/session-start', ({ agent, source }): void => {
      // Master switch: fully off. No scanning, no decide, no verdict log.
      if (!engine.enabled) return
      void (async () => {
        try {
          const event: GuardEvent = {
            eventType: 'agent/session-start',
            agentId: agent.id,
            sessionId: agent.id,
            data: { source },
            context: { agentId: agent.id },
          }
          const decision = await resolveDecision(options, engine, event, sessionRouteOf(agent))
          logDecision(ctx, 'agent/session-start', decision)
          recordVerdict(ctx, {
            hook: 'agent/session-start',
            sessionId: agent.id,
            decision,
          }, options.verdictLogPath, { recordAllow: options.recordAllow?.() ?? false })
        } catch (error) {
          ctx.logger.warn(`${PREFIX} agent/session-start review failed: ${error instanceof Error ? error.message : String(error)}`)
        }
      })()
    })
  }

  // ── subagent/start | subagent/end: observe-only lifecycle audit. The child
  // id IS a session id, so rows correlate with the child's own verdict rows.
  if (hooks.subagentLifecycle !== false) {
    // The subagent lifecycle events are declared by @deepseek-ai/dsh-subagent
    // (loaded by the host whenever subagents exist). It is deliberately not a
    // build dependency of this plugin, so the registration goes through a
    // widened-name cast with a locally typed payload (structural, like every
    // other harness face in this adapter).
    const onSubagent = ctx.on as unknown as
      (event: 'subagent/start' | 'subagent/end', listener: (info: SubagentEventInfo) => void) => unknown
    onSubagent('subagent/start', (info): void => {
      if (!engine.enabled) return
      recordSubagentEvent(ctx, options, engine, 'subagent/start', info.id, {
        provider: info.provider, local: info.local,
      })
    })
    onSubagent('subagent/end', (info): void => {
      if (!engine.enabled) return
      const output = extractBlocksText(info.lastAssistantMessage)
      recordSubagentEvent(ctx, options, engine, 'subagent/end', info.id, {
        provider: info.provider, local: info.local, stopReason: info.stopReason,
      }, output.length > 0 ? truncateForScan(output) : undefined)
    })
  }

  if (hooks.systemPromptAssemble !== false && options.promptGuard !== false) {
    ctx.on('system-prompt/assemble', async (_assembly, context, next): Promise<PromptAssembly> => {
      let section: AssembledSection
      try {
        // Master switch: when the guard is disabled the security section is
        // not injected either. The engine already allows everything, so the
        // instruction injection would only mislead the model into thinking a
        // guard is still active.
        if (!engine.enabled) return next()
        const scope = context.scope
        const sessionKey = scope !== undefined && typeof scope === 'object' && scope !== null
          && typeof (scope as { id?: unknown }).id === 'string'
          ? (scope as { id: string }).id
          : undefined
        section = buildPromptGuardSection(options.state, sessionKey)
      } catch (error) {
        ctx.logger.warn(`${PREFIX} prompt-guard section failed: ${error instanceof Error ? error.message : String(error)}`)
        return next()
      }
      // next() is invoked exactly once (the section is built before it), so a
      // later spread/throw cannot double-delegate downstream.
      const assembled = await next()
      return {
        ...assembled,
        sections: [...assembled.sections, section],
      }
    })
  }

  // State cleanup: a disposed agent's state must never leak into a reused id.
  ctx.on('agent/disposed', (payload) => {
    options.state.clearSession(payload.agent.id)
  })

  // ── ctx.tools.guard(): the monotonic, deny-only invariant that runs AFTER
  // the whole tools/pre-execute waterfall. A block verdict denies with its
  // reason; every other action abstains (no guard can force-allow a call
  // another policy denied, and listener ordering cannot resurrect a call this
  // invariant forbids). The seam is SYNCHRONOUS, so only the rule stage runs
  // here — the model stage cannot be awaited at this boundary.
  //
  // The tools service may not be up yet when the guard loads (fiber order), so
  // install lazily: try now, then on every 'internal/service' event (the same
  // pattern the /guard/api routes use for webServer).
  if (hooks.toolsGuard !== false) {
    let installed = false
    const installGuard = (): void => {
      if (installed) return
      // cordis `ctx.get` returns undefined (never throws) for an unprovided service.
      const tools = ctx.get('tools') as { guard(guard: (execution: ToolExecution) => string | undefined): () => void } | undefined
      if (tools === undefined || typeof tools.guard !== 'function') return
      const disposer = tools.guard((exec): string | undefined => {
        // Master switch: fully off. No scanning, no decide, no verdict log.
        if (!engine.enabled) return undefined
        const event = toToolEvent('tools/guard', exec)
        try {
          Object.assign(event.data, deriveToolCallFeatures(exec.arguments as Record<string, unknown>, { workspaceRoot: options.workspaceRoot }))
        } catch {
          // the invariant still evaluates on whatever features were derived
        }
        const decision = engine.decide(event)
        if (decision.action === 'block') {
          logDecision(ctx, 'tools/guard', decision)
          recordVerdict(ctx, {
            hook: 'tools/guard',
            sessionId: exec.agent?.id,
            decision,
            tool: exec.name,
            callId: exec.callId,
            turn: currentTurn(exec.agent?.session),
          }, options.verdictLogPath, { recordAllow: options.recordAllow?.() ?? false })
          return reason(decision, 'tool call blocked', options.lang?.() ?? 'en')
        }
        return undefined
      })
      installed = true
      ctx.effect(() => disposer, 'guard-tools-guard-invariant')
    }
    installGuard()
    if (!installed) {
      ctx.on('internal/service', (name: string) => {
        if (name === 'tools') installGuard()
      })
    }
  }
}

/**
 * How many continuations one (session, turn) may be forced into by a blocking
 * `agent/turn-stopping` verdict. The harness does not cap stop-steering yet
 * (its TODO(stop-loop-guard)), so the guard self-limits: a policy that keeps
 * rejecting every stop would otherwise loop the agent forever.
 */
const STOP_STEER_CAP = 3

/**
 * Text of the agent's LAST assistant message (the answer about to close the
 * turn) — the content the `agent/turn-stopping` review inspects. Scans the
 * session log backwards; the stop boundary follows the final assistant
 * message, so the first hit is the right one. Empty when none was produced.
 */
function lastAssistantText(agent: Agent): string {
  try {
    const events = agent.session.events as readonly unknown[]
    for (let i = events.length - 1; i >= 0; i--) {
      const event = events[i] as { type?: unknown; data?: { message?: { content?: unknown } } } | undefined
      if (event?.type !== 'assistant/message') continue
      const text = extractBlocksText(event.data?.message?.content)
      if (text.length > 0) return truncateForScan(text)
      return ''
    }
  } catch {
    // contained: a session-log hiccup must not break the stop boundary
  }
  return ''
}

/** Concatenate the text blocks of a ContentBlock-like array (unknown-shaped). */
function extractBlocksText(blocks: unknown): string {
  if (!Array.isArray(blocks)) return ''
  const parts: string[] = []
  for (const block of blocks) {
    if (block !== null && typeof block === 'object'
      && (block as { type?: unknown }).type === 'text'
      && typeof (block as { text?: unknown }).text === 'string') {
      parts.push((block as { text: string }).text)
    }
  }
  return parts.join('\n')
}

/**
 * Extract the most recent USER-ROLE message text from the agent's session log,
 * for the model stage's `{user_query}` placeholder. `agent/pre-step` events
 * carry the full messages array in `data.messages`, but `tools/pre-execute`
 * events don't — the intent-drift and risk-instruction audit templates need a
 * `<USER_REQUEST>` to compare the tool call against, so the adapter feeds one
 * here. Scans backwards for the latest `user/message`; empty when none exists.
 */
function recentUserTextOf(agent: {
  session?: { events?: readonly unknown[] | undefined } | undefined
} | null | undefined): string {
  try {
    const events = agent?.session?.events as readonly unknown[] | undefined
    if (!Array.isArray(events)) return ''
    for (let i = events.length - 1; i >= 0; i--) {
      const event = events[i] as { type?: unknown; data?: { content?: unknown } } | undefined
      if (event?.type !== 'user/message') continue
      const text = extractBlocksText(event.data?.content)
      if (text.length > 0) return truncateForScan(text)
    }
  } catch {
    // contained: a session-log hiccup must never break the tool-call path
  }
  return ''
}

/**
 * Structural face of the `subagent/start` / `subagent/end` payloads (declared
 * authoritatively by @deepseek-ai/dsh-subagent).
 */
interface SubagentEventInfo {
  /** Unique identity shared with the paired terminal event. */
  runId: string
  /** The provider name recorded when the child was created. */
  provider: string
  /** The child agent's id (a session id). */
  id: string
  /** Whether a local child agent was present at start. */
  local: boolean
  /** The terminal stop reason (`subagent/end` only). */
  stopReason?: string
  /** The child's final assistant output (`subagent/end` only). */
  lastAssistantMessage?: unknown[]
}

/**
 * Record one observe-only subagent lifecycle verdict. Never vetoes (the
 * subagent seams are emit notifications); the row is keyed to the CHILD
 * session id so it correlates with the child's own verdict rows, and the
 * child's final output text is reviewed like any other content.
 */
function recordSubagentEvent(
  ctx: Context,
  options: AdapterOptions,
  engine: GuardEngine,
  hook: 'subagent/start' | 'subagent/end',
  sessionId: string,
  data: Record<string, unknown>,
  content?: string,
): void {
  void (async () => {
    try {
      const event: GuardEvent = {
        eventType: hook,
        agentId: sessionId,
        sessionId,
        ...(content !== undefined ? { content } : {}),
        data: content !== undefined ? { ...data, content } : data,
        context: { agentId: sessionId },
      }
      const decision = await resolveDecision(options, engine, event, undefined)
      logDecision(ctx, hook, decision)
      recordVerdict(ctx, {
        hook,
        sessionId,
        decision,
        content,
      }, options.verdictLogPath, { recordAllow: options.recordAllow?.() ?? false })
    } catch (error) {
      ctx.logger.warn(`${PREFIX} ${hook} review failed: ${error instanceof Error ? error.message : String(error)}`)
    }
  })()
}
