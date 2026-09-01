/**
 * Threat pattern library: plain data (regex lists / token lists) shared by the
 * feature extractors. No logic lives here. Every regex runs against
 * NORMALIZED text (lowercase, invisible chars stripped, whitespace collapsed)
 * or, where noted, the compact variant.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/patterns
 */

/** High-risk command patterns (normalized text).
 *
 * The `rm` family is expressed in the repeated-flag form
 * (`(?:-[a-z]+\s+)+`) which also covers single-flag invocations
 * (`rm -rf /` == `-rf `), so only the `/*` and top-level-dir variants need
 * dedicated rows. Reverse-shell rows (`nc -e`, `socat … EXEC:`, bash
 * `/dev/tcp` redirection) are high-confidence network code-execution sinks.
 *
 * Whole-text rows only: statement/binary-sensitive terms whose bare word would
 * false-positive on ordinary prose (`grep -r reboot …`, `echo "shutdown the
 * server" >> notes`) live in {@link HIGH_RISK_HEAD_PATTERNS} and are matched
 * at shell-segment heads by the feature extractor. */
export const HIGH_RISK_PATTERNS: readonly RegExp[] = [
  /\brm\s+-[a-z]*r[a-z]*f?\s+\/\*/,
  /\brm\s+(?:-[a-z]+\s+)+\/\s*(\s|$)/,
  /\brm\s+(?:-[a-z]+\s+)+~\s*(\s|$)/,
  /\brm\s+(?:-[a-z]+\s+)+\*\s*$/,
  /\brm\s+[^\n|;&]*--no-preserve-root/,
  /\brm\s+-[a-z]*r[a-z]*f?\s+\/(home|root|etc|usr|boot|var|bin|opt)\b/,
  /\|\s*(ba|z|da|k)?sh\b/,
  /\b(?:nc|ncat|netcat)\b[^\n]*-e\b/,
  /\bsocat\b[^\n]*\bexec:/,
  /\b(?:exec|(?:ba|z|da|k)?sh)\b[^\n]*\/dev\/(?:tcp|udp)\b/,
  // The Windows face of operator_rules 705 REMOTE_INSTALL_CHAIN: PowerShell
  // download-and-execute cradles (IEX/Invoke-Expression).
  /\bpowershell\b[^\n]*\b(?:iex|invoke-expression)\b/,
]

/**
 * High-risk terms that only count at the head of a shell segment (`shutdown`,
 * `sudo reboot`, `mkfs.ext4 /dev/sda`, `format c:`, `while true; …`), never
 * when the same word merely appears in text (`grep -r reboot /etc/systemd`,
 * `echo "shutdown the server" >> notes.md`, `node -e "while(true){}"`).
 * Matched against each normalized segment head by the feature extractor
 * (`sudo`/`env`/`time`/… prefixes are skipped first).
 */
export const HIGH_RISK_HEAD_PATTERNS: readonly RegExp[] = [
  /^shutdown\b/,
  /^reboot\b/,
  /^systemctl\s+(?:reboot|poweroff)(?:\s|$)/,
  /^mkfs(?:\.|$)/,
  /^format\s+[a-z]:/,
  /^diskutil\s+erase/,
  /^while\s+(?:true\b|\(1\)|:)/,
  /^for\s*\(\s*;+\s*\)/,
]

/** High-risk patterns against the compact variant (defeats letter-spacing).
 *
 * The compact variant is a SINGLE continuous token of alphanumerics (no word
 * boundaries), so these are unanchored substring matches: `sudo r m - r f /`
 * compacts to `sudormrf`, which must still hit. Inputs like `r m - r f /`
 * (→ `rmrf`), plain `rm -rf /` (→ `rmrf`) and `rm -fr /` (→ `rmfr`) are
 * covered by the same rows.
 *
 * Deliberately NOT included: `while`/`for` loop rows. Their letter-spaced
 * forms (`w h i l e  t r u e`) still match the NORMALIZED head-gated rows
 * (whitespace survives normalization), and a compact scan would otherwhise
 * false-positive on embedded busy-loops like `node -e "while(true){}"` (B4#4).
 * Known trade-off (N6): `wh i l e t r u e` fully letter-spaced is a head-gated
 * normalized miss (compact is what breaks letter-spacing, and compact strips
 * nothing here because the segments collapse). Loop-body/exfil features and the
 * command-layer exfiltration chain still catch malicious consumed loops.
 */
export const HIGH_RISK_COMPACT_PATTERNS: readonly RegExp[] = [
  /rmrf?/,
  /rmfr/,
]

/** Shell rc truncation / persistent backdoor writes.
 * `:> ~/.bashrc` is already caught by the `>>?` row (the `>` sits inside the
 * `:>` token), so only the `truncate` form needs its own row. */
export const SHELL_RC_TRUNCATION_PATTERNS: readonly RegExp[] = [
  />>?\s*(?:~\/)?\.(?:bashrc|zshrc|profile|bash_profile|zprofile)\b/,
  /truncate\s+-s\s+0\s+(?:~\/)?\.(?:bashrc|zshrc|profile)\b/,
]

/** Command obfuscation / encoded-delivery indicators (normalized text). */
export const OBFUSCATION_PATTERNS: readonly RegExp[] = [
  /\bbase64\s+(-d|--decode)\b[^\n|]*\|/,
  /\bxxd\s+-r\b/,
  /\bopenssl\s+enc\s+-d\b/,
  /\bprintf\s+['"][^'"]*\\x[0-9a-f]{2}/,
  /\bsh\s+-c\s+['"][^'"]*\\x[0-9a-f]{2}/,
  /\becho\s+['"][^'"]*\\x[0-9a-f]{2}/,
  /\bcertutil\s+-decode\b/,
  /\b(bash|sh)\s+(?:-c\s+)?['"]?\s*(?:echo|printf)\b[^|]*\|\s*(?:ba|z|da|k)?sh\b/,
]

/** Protected path tokens; matched against any path candidate. */
export const PROTECTED_PATH_TOKENS: readonly string[] = [
  '.ssh', '.gnupg', '.npmrc', '.netrc', '.dsh', 'cordis.yml', 'cordis.patch.yml',
  '/etc/sudoers', '/etc/passwd', '/etc/shadow', '.aws/credentials',
]

/** Home-level shell rc tokens; only matched for absolute / ~ / $-prefixed candidates. */
export const HOME_RC_TOKENS: readonly string[] = [
  '.bashrc', '.zshrc', '.profile', '.bash_profile', '.zprofile', '.bash_login',
]

/** Whole-token delete verbs (normalized). */
export const DELETE_VERBS: readonly string[] = [
  'rm', 'rmdir', 'unlink', 'shred', 'truncate', 'wipe', 'erase', 'del', 'deltree', 'rd',
]

/** `find <start> … -delete` deletion form. */
export const FIND_DELETE_RE = /\bfind\b[^\n]*\s-delete\b/

/** Outbound network sinks.
 *
 * Simple verbs require a trailing boundary (`(?=[\s;|&()]|$)`) so path
 * tokens like `~/.ssh/id_rsa`, `ssh-notes.txt` or `ping.txt` are not
 * misread as network commands. `/dev/tcp|udp` is a bash-only socket
 * facility with no legitimate non-network use, so any reference counts.
 * `echo`/`printf` first-token exemption lives in features.ts. */
export const OUTBOUND_PATTERNS: readonly RegExp[] = [
  /\b(?:curl|wget|fetch|nc|ncat|netcat|socat|telnet|ping|ssh|scp|rsync)\b(?=[\s;|&()]|$)/,
  /\bgit\s+(?:push|clone|fetch|pull)\b/,
  /\bpython\S*\s+[^\n]*(?:requests|urllib|socket|smtplib|http\.client)\b/,
  /\bnode\s+[^\n]*(?:http|https|net|dgram|axios|fetch)\b/,
  /\binvoke-(webrequest|restmethod|expression)\b/,
  /\/dev\/(?:tcp|udp)\b/,
]

/** Secret references inside commands (normalized text). */
export const SECRET_REF_PATTERNS: readonly RegExp[] = [
  /\b(api[_-]?key|apikey|access[_-]?key|secret|token|password|passwd|pwd|credential|cred|auth[_-]?token|bearer|private[_-]?key)\b/,
  /\benv\s+[a-z0-9_]*(?:key|token|secret|password|credential)[a-z0-9_]*=/,
  /\.env\b/,
  /github_pat_|ghp_|gho_|glpat-|sk-|AKIA[0-9A-Z]{16}/,
]

/** Encoding-transform indicators (source→transform legs of an exfil chain). */
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
]

/** Tool-result control tokens stripped before scanning (until stable). */
export const SPECIAL_TOKENS: readonly string[] = [
  '<system>', '</system>', '<assistant>', '</assistant>', '<user>', '</user>',
  '<tool>', '</tool>', '<tool_response>', '</tool_response>', '<output>', '</output>',
]

/** Script file extensions for artifact provenance. */
export const SCRIPT_EXTENSIONS: readonly string[] = [
  '.sh', '.bash', '.zsh', '.py', '.rb', '.pl', '.ps1', '.js', '.ts', '.lua',
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
