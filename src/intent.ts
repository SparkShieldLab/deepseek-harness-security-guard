/**
 * User-intent threat features: detect prompt-level attack intents (disable
 * the guard, bypass approval, ignore restrictions) in the user-role message
 * text that feeds `agent/pre-step`.
 *
 * Mirrors the tool-layer feature contract: fields are ONLY present when a
 * signal fired, so baseline rules only match real hits. English patterns run
 * on plain lowercase text; the `.{0,24}` windows span intervening words
 * (`disable the safety guard`), and dense variants defeat letter-spacing
 * tricks (`d i s a b l e  s a f e t y`). Chinese patterns live in the
 * plain table because the dense form strips every non-alphanumeric char,
 * which removes CJK.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/intent
 */

import { scanViews } from './normalize.ts'

/** Risk level of a matched user-intent pattern. */
export type IntentRisk = 'block' | 'warn'

/** Features derived from one user-message scan. */
export interface UserIntentFeatures {
  /** 'block': direct attack wording; 'warn': softer manipulation. Present only on a hit. */
  userIntentRisk?: IntentRisk
  /** Id of the matched pattern, for audit and policy messages. */
  intentMatch?: string
}

/** Block-level patterns matched against NORMALIZED lowercase text. */
const BLOCK_PATTERNS: readonly { id: string; re: RegExp }[] = [
  {
    id: 'disable-guard',
    re: /\b(?:disable|deactivate|turn off|shut down)\b.{0,24}\b(?:safety|guardrails?|guard|security|defenses?|protection)\b/,
  },
  {
    id: 'bypass-approval',
    re: /\b(?:bypass|circumvent|skip|dodge|avoid)\b.{0,24}\b(?:approval|authorization|permission)\b/,
  },
  {
    id: 'ignore-restrictions',
    re: /\b(?:ignore|disregard|remove|override|waive)\b.{0,24}\b(?:restrictions?|constraints?|guidelines?|boundaries?|limits?)\b/,
  },
  {
    // N12: the "ignore all previous instructions" jailbreak family. The
    // time qualifier (earlier/prior/previous/above + instructions) keeps
    // innocent phrasing like "ignore the instructions in the README" from
    // matching.
    id: 'ignore-instructions',
    re: /\b(?:override|ignore|disregard)\s+(?:any\s+|all\s+)?(?:earlier|previous|prior|above)\s+instructions?\b/,
  },
  {
    id: 'disable-guard-config',
    re: /\bagent[-_ ]?security[-_ ]?guard\b.{0,24}\b(?:disable|deactivate|turn off|shut down|off|basepolicies)\b/,
  },
  {
    id: 'chinese-bypass',
    re: /(?:绕过|跳过)(?:审批|授权)|禁用(?:安全|防护|守卫)|关闭(?:安全|防护)|忽略(?:安全|规则|限制)/,
  },
  {
    // N12: the Chinese "ignore all previous instructions" family (the time
    // qualifier keeps innocent phrasing like "ignore the instructions in the
    // README" from matching).
    id: 'chinese-ignore-instructions',
    re: /忽略(?:之前|先前|上面)(?:所有|全部)?(?:的)?(?:指令|指示)/,
  },
  // ---- operator_rules.yml merge (2026-08-31): intent-layer block family ----
  {
    // 101 jailbreak keyword family. Discussion contexts (tutorials/research)
    // are downgraded to warn by the discussion cue.
    id: 'jailbreak-keywords',
    re: /\b(?:dan mode|developer mode|unrestricted mode|jailbreak(?:ing|s)?|ai jailbreak)\b/,
  },
  {
    id: 'chinese-jailbreak',
    re: /(?:ai|提示词|模型)?越狱(?:攻击|模式)|无限制模式/,
  },
  {
    // 606 memory backdoor: trigger word → action conditional instruction.
    id: 'memory-backdoor',
    re: /\b(?:when|if)\b[^.\n]{0,40}\b(?:keyword|trigger|phrase|code word|secret phrase)\b[^.\n]{0,40}\b(?:then|must|always)\b[^.\n]{0,40}\b(?:ignore|execute|run|send|reveal|exfiltrate|upload)\b/,
  },
  {
    id: 'chinese-memory-backdoor',
    re: /(?:触发词|暗号|口令)[^。\n]{0,40}(?:忽略|执行|发送|泄露|上传)/,
  },
  {
    id: 'hidden-instruction',
    re: /store (?:this|the) hidden instructions? (?:for|in) (?:future|later) sessions?/,
  },
]

/** Dense-form (all non-alphanumerics stripped) block patterns. English only (CJK is stripped by the dense form). */
const BLOCK_COMPACT_PATTERNS: readonly { id: string; re: RegExp }[] = [
  {
    id: 'disable-guard',
    re: /disablesafety|disabletheguard|turnoffsafety|deactivatesafety|killtheguard|stopsafety/,
  },
  {
    id: 'bypass-approval',
    re: /bypassapproval|skipapproval|dodgeapproval|bypassauthorization/,
  },
  {
    id: 'ignore-restrictions',
    re: /ignorerestrictions|removerestrictions|overriderules|disregardrules|waiverules/,
  },
  // operator_rules merge: the jailbreak dense row. A bare "dan" must never
  // enter this table — the dense form of "abundance" contains "dan", a
  // guaranteed false positive.
  { id: 'jailbreak-keywords', re: /jailbreak|developermode|unrestrictedmode/ },
]

/** Warn-level patterns matched against NORMALIZED lowercase text. */
const WARN_PATTERNS: readonly { id: string; re: RegExp }[] = [
  {
    id: 'pretend-unrestricted',
    re: /\b(?:pretend|act as if|imagine|behave as)\b.{0,40}\b(?:no restrictions?|unrestricted|without (?:restrictions?|safety|guardrails?)|no safety|no guardrails?)\b/,
  },
  {
    id: 'ask-bypass-howto',
    re: /\b(?:how (?:do|can|would)|what.{0,16}(?:way|methods?))\b.{0,24}\b(?:bypass|circumvent|disable|defeat)\b/,
  },
  {
    id: 'chinese-soft',
    re: /假装没有限制|不受限制|无视规则/,
  },
  // ---- operator_rules.yml merge (2026-08-31): intent-layer warn family ----
  {
    // 102 role impersonation (complements the existing pretend-unrestricted:
    // system/admin framings).
    id: 'role-impersonation',
    re: /\b(?:you are now|act as|pretend (?:that )?you are|switch to)\b.{0,24}\b(?:unrestricted|developer mode|administrator|root user|no[- ]guardrails?)\b/,
  },
  {
    id: 'chinese-role-impersonation',
    re: /(?:扮演|假装|切换为)[^。\n]{0,16}(?:系统|开发者|管理员|无限制|无约束)/,
  },
  {
    // 105 context probing.
    id: 'context-probe',
    re: /\b(?:show|reveal|print|dump|export|display)\b.{0,24}\b(?:system prompt|conversation history|hidden context|developer message|hidden instructions?)\b/,
  },
  {
    id: 'chinese-context-probe',
    re: /(?:展示|泄露|打印|导出)[^。\n]{0,16}(?:系统提示词|会话历史|隐藏上下文|开发者消息)/,
  },
  {
    // 106 agent memory read/export (patterns run on the normalizeText output,
    // all lowercase).
    id: 'memory-read',
    re: /\b(?:read|reveal|export|show|retrieve|dump)\b.{0,24}\b(?:saved memory|long[- ]term memory|(?:memory|soul|identity)\.md)\b/,
  },
  {
    id: 'chinese-memory-read',
    re: /(?:读取|展示|导出|检索)[^。\n]{0,16}(?:智能体)?(?:长期)?记忆/,
  },
  {
    // 108 workspace escape inducement.
    id: 'workspace-escape',
    re: /\b(?:write|read|access|modify|list)\b.{0,24}\b(?:outside|beyond)\b.{0,12}\bworkspace\b|\b(?:access|traverse)\b.{0,16}\b(?:parent director(?:y|ies)|host filesystem)\b/,
  },
  {
    id: 'chinese-workspace-escape',
    re: /(?:逃逸|绕过|突破)[^。\n]{0,8}(?:工作区|目录限制|文件系统限制)|(?:查看|列出)[^。\n]{0,20}(?:工作区外|父目录|宿主机)[^。\n]{0,20}文件/,
  },
  {
    // 302 verbatim tool-argument injection.
    id: 'argument-manipulation',
    re: /\b(?:pass|use)\b.{0,12}\bthis\b.{0,12}\b(?:directly|exactly|verbatim)\b.{0,24}\btool\b|\brun this command verbatim\b|\bdo not (?:modify|validate|sanitize) the (?:arguments|parameters|tool input)\b/,
  },
  {
    id: 'chinese-argument-manipulation',
    re: /(?:原样|直接)[^。\n]{0,8}(?:传入|作为)[^。\n]{0,8}(?:工具参数|工具输入)/,
  },
  {
    // 801/803 malicious MCP/plugin/skill inducement.
    id: 'malicious-extension',
    re: /\b(?:mcp server|mcp tool|plugin|skill)\b.{0,40}\b(?:exfiltrate|upload|steal|disable security|bypass approval|read credentials)\b/,
  },
  {
    id: 'chinese-malicious-extension',
    re: /(?:mcp|插件|skill)[^。\n]{0,24}(?:窃取|外发|执行任意|绕过校验|关闭安全|绕过审批|读取凭证|上传密钥)/,
  },
  {
    // 603 forged sources.
    id: 'forged-source',
    re: /\b(?:fabricate|forge|invent)\b.{0,16}\b(?:citation|source|reference|url)\b|claim (?:that )?this came from (?:an )?(?:official|trusted) source/,
  },
  {
    id: 'chinese-forged-source',
    re: /(?:伪造|编造)[^。\n]{0,12}(?:引用|来源|参考文献|链接)/,
  },
  {
    // 601 knowledge-base poisoning instructions (one row per word order in
    // each language: knowledge base → write → instruction / instruction →
    // write → knowledge base).
    id: 'knowledge-poison',
    re: /\b(?:insert|append|write|upload)\b.{0,24}\b(?:instruction|payload|prompt)\b.{0,24}\b(?:knowledge base|vector (?:store|db)|retrieval corpus)\b|when retrieved\b.{0,24}\b(?:ignore|override|execute)\b/,
  },
  {
    id: 'chinese-knowledge-poison',
    re: /(?:知识库|向量库|检索库)[^。\n]{0,24}(?:写入|插入|上传)[^。\n]{0,24}(?:指令|载荷|提示词)|(?:指令|载荷|提示词)[^。\n]{0,12}(?:写入|插入|上传)[^。\n]{0,12}(?:知识库|向量库|检索库)/,
  },
]

/**
 * Cues that the matched phrase is part of *discussing* the guard (quoting docs,
 * tutorials, or asking how it works) rather than directly instructing the
 * model to disable/bypass it. Curiosity questions ("How do jailbreaks work?",
 * "How do I jailbreak?") are discussion, not attack directives — same treatment. "The docs say: to disable the safety guard, edit
 * config.yml" quotes documentation, a legitimate developer question, not an
 * attack (S7).
 */
const DISCUSSION_CUE_RE = /\b(?:docs?|documentation|tutorial|guide|manual|article|explain|explains|explanation|describe|describes|quote|quoting|says?|said|saying|reading|learn|teach|how to|how (?:do|does|did)|what (?:is|are)|in order to|example|screenshot|walkthrough)\b|(?:如何|怎么|什么是|原理)/

function hasDiscussionCue(text: string, matchIndex: number): boolean {
  const before = text.slice(Math.max(0, matchIndex - 80), matchIndex)
  if (DISCUSSION_CUE_RE.test(before)) return true
  // Chinese questions often place the question word after the object ("how is
  // a jailbreak attack carried out"), so looking ahead is not enough: also
  // scan a short window after the match. The downgrade is always warn, never
  // a silent allow (N2).
  const after = text.slice(matchIndex, matchIndex + 40)
  return DISCUSSION_CUE_RE.test(after)
}

/** Scan one user-message text for attack intents. Fields appear only on a hit. */
export function deriveUserIntentFeatures(text: string): UserIntentFeatures {
  const { plain, dense } = scanViews(text)
  for (const { id, re } of BLOCK_PATTERNS) {
    const match = re.exec(plain)
    if (match !== null) {
      // A discussion cue ("Per the docs, …") suppresses the block but must not
      // silently swallow the attack phrase: degrade to warn so the intent is
      // still surfaced (N2). A bare "Per the documentation, disable the safety
      // guard." no longer bypasses to allow entirely.
      if (hasDiscussionCue(plain, match.index)) return { userIntentRisk: 'warn', intentMatch: id }
      return { userIntentRisk: 'block', intentMatch: id }
    }
  }
  for (const { id, re } of BLOCK_COMPACT_PATTERNS) {
    if (re.test(dense)) return { userIntentRisk: 'block', intentMatch: id }
  }
  for (const { id, re } of WARN_PATTERNS) {
    if (re.test(plain)) return { userIntentRisk: 'warn', intentMatch: id }
  }
  return {}
}
