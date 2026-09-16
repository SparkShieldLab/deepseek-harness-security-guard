/**
 * Platform-NEUTRAL threat pattern library: plain data (regex lists / token
 * lists) shared by the feature extractors and true across shells and OSes —
 * prompt-injection phrases, control tokens, secret references, encoding
 * transforms, script extensions, shebangs.
 *
 * Platform-VARYING rows (high-risk commands, delete verbs, protected paths,
 * obfuscation, outbound sinks, privilege escalation, system-path writes,
 * sandbox escapes, recon, …) live in `threat-catalog.ts` and are selected at
 * runtime from the host platform. The `*_PATTERNS` aliases at the bottom of
 * this file re-export the POSIX (Linux) catalogue purely for unit tests and
 * legacy imports; RUNTIME code must read `activeThreatCatalog()` instead.
 *
 * Every regex runs against NORMALIZED text (lowercase, invisible chars
 * stripped, whitespace collapsed) or, where noted, the compact variant.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/patterns
 */

import { buildThreatCatalog } from './threat-catalog.ts'

/** Secret references inside commands (normalized text). */
export const SECRET_REF_PATTERNS: readonly RegExp[] = [
  /\b(api[_-]?key|apikey|access[_-]?key|secret|token|password|passwd|pwd|credential|cred|auth[_-]?token|bearer|private[_-]?key)\b/,
  /\benv\s+[a-z0-9_]*(?:key|token|secret|password|credential)[a-z0-9_]*=/,
  /\.env\b/,
  /github_pat_|ghp_|gho_|glpat-|sk-|AKIA[0-9A-Z]{16}/,
]

/** Encoding-transform indicators (source→transform legs of an exfil chain).
 * Includes the Windows faces (`Convert.ToBase64String`, `certutil -encode`);
 * harmless where those tools do not exist. */
export const TRANSFORM_PATTERNS: readonly RegExp[] = [
  /\bbase64\b/,
  /\bxxd\b/,
  /\bhexdump\b/,
  /\bopenssl\b/,
  /\biconv\b/,
  /\bzip\s+-[a-z]*e\b/,
  /\bgzip\b/,
  /\b7z\b/,
  /\buuencode\b/,
  /\bconvert\.tobase64string\b/,
  /\bcertutil\s+-encode\b/,
]

/** Tool-result control tokens stripped before scanning (until stable). */
export const SPECIAL_TOKENS: readonly string[] = [
  '<system>', '</system>', '<assistant>', '</assistant>', '<user>', '</user>',
  '<tool>', '</tool>', '<tool_response>', '</tool_response>', '<output>', '</output>',
]

/** Script file extensions for artifact provenance. */
export const SCRIPT_EXTENSIONS: readonly string[] = [
  '.sh', '.bash', '.zsh', '.py', '.rb', '.pl', '.ps1', '.js', '.ts', '.lua',
  // Windows + macOS script forms (artifact provenance on those platforms).
  '.bat', '.cmd', '.vbs', '.hta', '.applescript', '.scpt',
]

/** Shebang at content start. */
export const SHEBANG_RE = /^#!\s*\S+/

/**
 * Tool-result injection phrase rules, grouped into five families. Each family
 * carries `direct` phrases (a single hit is already high-confidence) and
 * `weak` phrases (two hits from DIFFERENT families are required to flag).
 */
export const INJECTION_RULES: readonly { family: string; direct: readonly RegExp[]; weak: readonly RegExp[] }[] = [
  {
    family: 'persona-hijack',
    direct: [
      /you are now\b/,
      /act as (?:an? )?(?:assistant|agent|system)/,
      /from now on,? (?:you are|behave|act)/,
      /ignore (?:all )?(?:previous|prior|above) (?:instructions|rules|prompts?|messages)/,
      /disregard (?:all )?(?:previous|prior|above) (?:instructions|rules|prompts?|messages)/,
    ],
    weak: [
      /\bignore\b/,
      /\bdisregard\b/,
      /\bforget (?:all )?(?:previous|prior) (?:instructions|rules|prompts?)\b/,
    ],
  },
  {
    family: 'safeguard-defeat',
    direct: [
      /bypass(?:ing)? (?:the |your |this )?(?:security|safety|guard|policy|restriction|limitation)s?/,
      /disable (?:the |your |this )?(?:security|safety|guard|policy|restriction|limitation)s?/,
      /remove (?:the |your |this )?(?:security|safety|guard|policy|restriction|limitation)s?/,
      /turn off (?:the |your |this )?(?:security|safety|guard|policy|restriction|limitation)s?/,
      /do not follow (?:your |the )?(?:security|safety|guard|policy|restriction|limitation)s?/,
      /i am the (?:admin|administrator|owner|root)/,
      /you (?:have|need) (?:no|zero) (?:restrictions?|limitations?|rules?)/,
      /(?:security|safety|guard|policy|restriction|limitation)s? (?:are|is) (?:disabled|removed|off|bypassed)/,
    ],
    weak: [
      /\bbypass\b/,
      /\bdisable\b/,
      /\boverride\b/,
      /\bunfiltered\b/,
      /\buncensored\b/,
      /\badmin mode\b/,
      /\bdeveloper mode\b/,
    ],
  },
  {
    family: 'tool-luring',
    direct: [
      /run (?:this|the|a) (?:command|tool|script)\b/,
      /execute (?:this|the|a) (?:command|tool|script)\b/,
      /call (?:the|your) (?:bash|shell|exec|terminal|tool)\b/,
      /use (?:the|your) (?:bash|shell|exec|terminal|tool)\b/,
      /run (?:bash|shell|exec|terminal)\b/,
      /now (?:run|execute|call)\b/,
      /go ahead and (?:run|execute|call|use)\b/,
      /(?:send|make) a (?:request|call|command) to\b/,
    ],
    weak: [
      /\b(?:run|execute|call|use|invoke)\s+(?:bash|shell|exec|terminal|subprocess|os\.system|system\(\))\b/,
    ],
  },
  {
    family: 'exfiltration',
    direct: [
      /send (?:the |this |my )?(?:file|data|content|output|result|secret|key|token|password)s? (?:to|via)\b/,
      /upload (?:the |this |my )?(?:file|data|content|output|result|secret|key|token|password)s? (?:to|via)\b/,
      /post (?:the |this |my )?(?:file|data|content|output|result|secret|key|token|password)s? (?:to|via)\b/,
      /exfiltrat\w+\b/,
      /steal (?:the |this |my )?(?:file|data|content|output|result|secret|key|token|password)s?\b/,
      /leak (?:the |this |my )?(?:file|data|content|output|result|secret|key|token|password)s?\b/,
      /print (?:the |this |my )?(?:secret|key|token|password)s?\b/,
      /reveal (?:the |this |my )?(?:secret|key|token|password)s?\b/,
    ],
    weak: [
      /\b(?:send|upload|post|exfiltrat\w+|leak|steal|dump|transfer)\b/,
    ],
  },
  {
    family: 'privilege-escalation',
    direct: [
      /escalat\w+ (?:my |our |the )?(?:privileges?|permissions?|rights?)/,
      /give (?:me|myself|us) (?:root|admin|sudo)\b/,
      /make (?:me|myself|us) (?:root|admin|sudo)\b/,
      /sudo\s+su\b/,
      /chmod\s+[0-7]{3,4}\s+\/etc\b/,
      /chown\s+\w+\s+\/etc\b/,
    ],
    weak: [
      /\b(?:root|admin|sudo)\b/,
      /\bprivilege escalation\b/,
    ],
  },
]

// ---------------------------------------------------------------------------
// POSIX (Linux) catalogue aliases — TEST/LEGACY ONLY.
//
// Runtime feature extraction reads `activeThreatCatalog()`. These aliases
// expose the Linux rows under their historical names so existing unit tests
// keep asserting POSIX behavior without coupling to the platform selector.
// ---------------------------------------------------------------------------
const LINUX = buildThreatCatalog('linux')

/** @deprecated runtime reads `activeThreatCatalog().highRisk`. */
export const HIGH_RISK_PATTERNS = LINUX.highRisk
/** @deprecated runtime reads `activeThreatCatalog().highRiskHead`. */
export const HIGH_RISK_HEAD_PATTERNS = LINUX.highRiskHead
/** @deprecated runtime reads `activeThreatCatalog().highRiskCompact`. */
export const HIGH_RISK_COMPACT_PATTERNS = LINUX.highRiskCompact
/** @deprecated runtime reads `activeThreatCatalog().shellRcTruncation`. */
export const SHELL_RC_TRUNCATION_PATTERNS = LINUX.shellRcTruncation
/** @deprecated runtime reads `activeThreatCatalog().obfuscation`. */
export const OBFUSCATION_PATTERNS = LINUX.obfuscation
/** @deprecated runtime reads `activeThreatCatalog().protectedPathTokens`. */
export const PROTECTED_PATH_TOKENS = LINUX.protectedPathTokens
/** @deprecated runtime reads `activeThreatCatalog().homeRcTokens`. */
export const HOME_RC_TOKENS = LINUX.homeRcTokens
/** @deprecated runtime reads `activeThreatCatalog().deleteVerbs`. */
export const DELETE_VERBS = LINUX.deleteVerbs
/** @deprecated runtime reads `activeThreatCatalog().findDelete`. */
export const FIND_DELETE_RE = LINUX.findDelete
/** @deprecated runtime reads `activeThreatCatalog().outbound`. */
export const OUTBOUND_PATTERNS = LINUX.outbound
