/**
 * Platform-adaptive threat-rule catalogue.
 *
 * The guard's baseline policies match on FEATURE fields (`highRisk`,
 * `privEsc`, `systemPathWrite`, …), not on raw patterns — so adapting to a
 * platform is adapting the FEATURE EXTRACTION, i.e. which regex/token rows
 * feed those fields. This module is the one home for those platform-varying
 * rows:
 *
 *   shared   — signals that are shell/OS-neutral (injection-ish command
 *              shapes, path traversal, package-registry overrides, memory
 *              poisoning, `shutdown`, `while true`, `git clone` chains, …)
 *   posix    — Linux + macOS rows (`rm`, `chmod`, `/etc`, `~/.ssh`, `/dev/tcp`,
 *              `nsenter`, `systemctl`, reverse-shell sinks, …)
 *   win32    — Windows / PowerShell rows (`Remove-Item`, `takeown`, `icacls`,
 *              `reg add`, `Set-MpPreference`, `schtasks`, `Set-ExecutionPolicy`,
 *              `IEX`/LOLBins, `C:\Windows`, …)
 *   darwin   — macOS-only rows layered on top of `posix` (`diskutil`,
 *              `osascript do shell script`, `csrutil disable`, `spctl`,
 *              `~/Library/Launch*`, …)
 *
 * `buildThreatCatalog(platform)` merges `shared` with the platform set; the
 * result is memoized for the process. `process.platform` is a process
 * constant, but the active catalogue is still set explicitly by the plugin
 * (see `index.ts`) so tests and forced-shell deployments can override it.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/threat-catalog
 */

import type { GuardPlatform } from './platform.ts'

/** Every platform-varying rule family consumed by the feature extractors. */
export interface ThreatCatalog {
  /** Whole-text high-risk command rows (`normalized` text). */
  highRisk: readonly RegExp[]
  /** High-risk terms gated to a shell-segment head. */
  highRiskHead: readonly RegExp[]
  /** Letter-spacing-proof `rm -rf`-family rows (compact text). */
  highRiskCompact: readonly RegExp[]
  /** Shell rc / profile truncation (persistence) rows. */
  shellRcTruncation: readonly RegExp[]
  /** Obfuscation / encoded-delivery rows. */
  obfuscation: readonly RegExp[]
  /** Protected path substrings (matched on candidate paths). */
  protectedPathTokens: readonly string[]
  /** Home-level rc tokens, only for absolute / `~` / `$` candidates. */
  homeRcTokens: readonly string[]
  /** Whole-token delete verbs. */
  deleteVerbs: readonly string[]
  /** `find … -delete`-style deletion form. */
  findDelete: RegExp
  /** Outbound network sinks. */
  outbound: readonly RegExp[]
  /** Command heads that execute a referenced path. */
  execHeads: readonly string[]
  /** Privilege escalation / security-control disable (block tier). */
  privEscBlock: readonly RegExp[]
  /** Privilege escalation (warn tier). */
  privEscWarn: readonly RegExp[]
  /** Writes into system persistence locations (block tier). */
  systemPathWriteBlock: readonly RegExp[]
  /** Installs into system bin/lib dirs (warn tier). */
  systemPathWriteWarn: readonly RegExp[]
  /** In-place guard/policy file tampering. */
  configTamper: readonly RegExp[]
  /** Sandbox / container escape (block tier). */
  sandboxEscapeBlock: readonly RegExp[]
  /** Sandbox / container escape (warn tier). */
  sandboxEscapeWarn: readonly RegExp[]
  /** Network recon / listener rows. */
  netRecon: readonly RegExp[]
  /** `../` traversal rows (both separators). */
  pathTraversal: readonly RegExp[]
  /** Clone-then-build chains. */
  untrustedSource: readonly RegExp[]
  /** Insecure registry/index override. */
  insecureRegistry: readonly RegExp[]
  /** Secret-looking values written to logs. */
  secretLogging: readonly RegExp[]
  /** Directive content aimed at memory-like targets. */
  memoryPoisonContent: readonly RegExp[]
  /** Memory-like write target (raw path, case preserved). */
  memoryTarget: RegExp
}

/** Rows shared by every platform. */
const SHARED: ThreatCatalog = {
  highRisk: [
    // PowerShell download-and-execute cradles (IEX / Invoke-Expression). `pwsh`
    // runs on Linux/macOS too, so these are cross-platform, not win32-only.
    /\b(?:powershell|pwsh)\b[^\n]*\b(?:iex|invoke-expression)\b/,
    /\b(?:iex|invoke-expression)\b[^\n]*(?:downloadstring|invoke-webrequest|iwr|new-object\s+net\.webclient)/,
    /\b(?:invoke-webrequest|iwr|downloadstring|start-bitstransfer)\b[^\n]*\|\s*(?:iex|invoke-expression)\b/,
  ],
  highRiskHead: [
    /^shutdown\b/,
    /^while\s+(?:true\b|\(1\)|:)/,
    /^for\s*\(\s*;+\s*\)/,
  ],
  highRiskCompact: [],
  shellRcTruncation: [],
  obfuscation: [],
  protectedPathTokens: [
    '.ssh', '.gnupg', '.npmrc', '.netrc', '.dsh', 'cordis.yml', 'cordis.patch.yml',
    '.aws/credentials', '.aws\\credentials',
  ],
  homeRcTokens: [],
  deleteVerbs: ['del', 'erase', 'rd', 'rmdir'],
  findDelete: /(?!)/,
  outbound: [
    /\b(?:curl|wget|fetch|nc|ncat|netcat|socat|telnet|ping|ssh|scp|rsync)\b(?=[\s;|&()]|$)/,
    /\bgit\s+(?:push|clone|fetch|pull)\b/,
    /\bpython\S*\s+[^\n]*(?:requests|urllib|socket|smtplib|http\.client)\b/,
    /\bnode\s+[^\n]*(?:http|https|net|dgram|axios|fetch)\b/,
  ],
  execHeads: ['sh', 'bash', 'zsh', 'dash', 'ksh', 'python', 'python3', 'node', 'ruby', 'perl', 'php', 'source', 'exec'],
  privEscBlock: [],
  privEscWarn: [],
  systemPathWriteBlock: [],
  systemPathWriteWarn: [],
  configTamper: [],
  sandboxEscapeBlock: [],
  sandboxEscapeWarn: [
    /\b(?:docker|podman)\s+run\b[^;\n]{0,60}--privileged/,
  ],
  netRecon: [
    /\b(?:nmap|masscan)\b/,
    /\bnc(?:at)?\b[^;\n]*(?:\s-l[a-z]*\b|\s--listen\b)/,
  ],
  pathTraversal: [
    /(?:\.\.[\/\\]){3,}/,
    /(?:\.\.[\/\\]){2,}\S*(?:\/etc\/|shadow|sudoers|\.aws\/|credentials)/,
  ],
  untrustedSource: [
    /\bgit\s+clone\b[^;\n]{0,120}(?:&&|;)[^;\n]{0,40}\b(?:install|build|setup|make)\b/,
  ],
  insecureRegistry: [
    /(?:npm_config_registry|pip_index_url)\s*=\s*http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)/,
  ],
  secretLogging: [
    /\b(?:console\.(?:log|debug|error|info)|logger?\.\w+|print)\s*\([^;\n]{0,80}\b(?:token|password|secret|api[_-]?key|apikey|cookie)\b/,
  ],
  memoryPoisonContent: [
    /\b(?:when|if)\b[^.\n]{0,40}\b(?:keyword|trigger|phrase|code word|secret phrase)\b[^.\n]{0,40}\b(?:then|must|always)\b[^.\n]{0,40}\b(?:ignore|execute|run|send|reveal|exfiltrate|upload)\b/,
    /store (?:this|the) hidden instructions? (?:for|in) (?:future|later) sessions?/,
    /(?:触发词|暗号|口令)[^。\n]{0,40}(?:忽略|执行|发送|泄露|上传)/,
  ],
  memoryTarget: /(?:^|[/\\\s])(?:memory|soul|identity)\.md$|\.claude[/\\]|\.claw[/\\]/i,
}

/** Linux + macOS rows. */
const POSIX: Partial<ThreatCatalog> = {
  highRisk: [
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
  ],
  highRiskHead: [
    /^reboot\b/,
    /^systemctl\s+(?:reboot|poweroff)(?:\s|$)/,
    /^mkfs(?:\.|$)/,
  ],
  highRiskCompact: [
    /rmrf?/,
    /rmfr/,
  ],
  shellRcTruncation: [
    />>?\s*(?:~\/)?\.(?:bashrc|zshrc|profile|bash_profile|zprofile)\b/,
    /truncate\s+-s\s+0\s+(?:~\/)?\.(?:bashrc|zshrc|profile)\b/,
  ],
  obfuscation: [
    /\bbase64\s+(-d|--decode)\b[^\n|]*\|/,
    /\bxxd\s+-r\b/,
    /\bopenssl\s+enc\s+-d\b/,
    /\bprintf\s+['"][^'"]*\\x[0-9a-f]{2}/,
    /\bsh\s+-c\s+['"][^'"]*\\x[0-9a-f]{2}/,
    /\becho\s+['"][^'"]*\\x[0-9a-f]{2}/,
    /\b(bash|sh)\s+(?:-c\s+)?['"]?\s*(?:echo|printf)\b[^|]*\|\s*(?:ba|z|da|k)?sh\b/,
  ],
  protectedPathTokens: [
    '/etc/sudoers', '/etc/passwd', '/etc/shadow',
  ],
  homeRcTokens: [
    '.bashrc', '.zshrc', '.profile', '.bash_profile', '.zprofile', '.bash_login',
  ],
  deleteVerbs: ['rm', 'unlink', 'shred', 'truncate', 'wipe'],
  findDelete: /\bfind\b[^\n]*\s-delete\b/,
  outbound: [
    /\/dev\/(?:tcp|udp)\b/,
  ],
  execHeads: [],
  privEscBlock: [
    /\bsetenforce\s+0\b/,
    /\b(?:systemctl|service)\s+(?:stop|disable|mask)\s+(?:firewalld|auditd|iptables|ufw|apparmor|selinux|defender)\b/,
    /\bchmod\s+(?:-[a-z]*r[a-z]*\s+|--recursive\s+)777\b/,
    /\bchown\s+root\b/,
    /\bchmod\s+[ug]+\+s\b/,
    /\bchmod\s+4[0-7]{3}\b/,
  ],
  privEscWarn: [
    /\bchmod\s+(?:[a-z]+\s+)?777\b/,
  ],
  systemPathWriteBlock: [
    /\btee\s+(?:-a\s+)?\/etc\/(?:cron\.d\/|crontab\b|rc\.local\b|profile\b)/,
    /(?:>>?)\s*\/etc\/(?:passwd|shadow|sudoers|crontab|profile|rc\.local)\b/,
    /(?:>>?)\s*\/etc\/cron\.d\//,
    /\bdd\b[^;\n]{0,40}of=\/etc\/(?:passwd|shadow|sudoers|crontab|profile|rc\.local)\b/,
  ],
  systemPathWriteWarn: [
    /\b(?:cp|mv|install|touch|ln|tee)\s+[^;\n]{0,80}\/usr\/(?:local\/)?bin\//,
  ],
  configTamper: [
    /(?:^|[;&|]\s*)(?:sudo\s+)?(?:sed\s+-i|perl\s+-pi)\b[^;\n]{0,80}\S*(?:policy|guardrail|agents\.md|skill\.md|claude\.md)/,
    /(?:echo\s+[^;\n]{0,200}>|tee\s+)\s*\S*(?:policy|guardrail|agents\.md|skill\.md|claude\.md)/,
    /(?:^|[;&|]\s*)(?:sudo\s+)?(?:rm|mv|chmod|chown)\s+[^;\n]{0,40}\S*(?:policy\.json|guardrail)/,
  ],
  sandboxEscapeBlock: [
    /\bnsenter\b/,
    /(?:^|[;&|]\s*)(?:sudo\s+)?chroot\s+\S/,
    /\/proc\/1\/root/,
    /\bdocker\s+run\b[^;\n]{0,60}-v\s+\/:/,
    /-v\s+[^;\n]*docker\.sock/,
    /--unix-socket\s+[^;\n]*docker\.sock/,
  ],
  netRecon: [],
  pathTraversal: [],
  untrustedSource: [],
  insecureRegistry: [],
  secretLogging: [],
  memoryPoisonContent: [],
  memoryTarget: SHARED.memoryTarget,
}

/** Windows / PowerShell rows. */
const WIN32: Partial<ThreatCatalog> = {
  highRisk: [
    // Encoded command delivery.
    /-e(?:nc|ncodedcommand)?\s+[a-z0-9+/=]{16,}/,
    // Disk / backup destruction.
    /\bformat\s+[a-z]:/,
    /\bvssadmin\s+delete\s+shadows/,
    /\bwbadmin\s+delete\s+catalog/,
    /\bdiskpart\b/,
    // Boot / recovery tampering.
    /\bbcdedit\b[^\n]*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)/,
    /\bcipher\s+\/w\b/,
    // Persistence / defense evasion.
    /\breg\s+(?:add|delete)\b[^\n]{0,60}hklm\\/,
    /\bschtasks\b[^\n]*\/create\b/,
    /\bsc(?:\.exe)?\s+create\b/,
    /\bnew-service\b/,
    /\bset-mppreference\b[^\n]*-disablerealtimemonitoring/,
    /\bstop-service\s+windefend\b/,
    /\bnetsh\s+advfirewall\s+set\s+state\s+off/,
    /\bset-executionpolicy\b[^\n]*bypass/,
    // Living-off-the-land binaries.
    /\b(?:mshta|rundll32|regsvr32)\b[^\n]*(?:http|javascript:|vbscript:|\.sct|\.hta)/,
    /\bcertutil\b[^\n]*(?:-urlcache|-decode)/,
    /\bbitsadmin\b[^\n]*\/transfer/,
    /\bwmic\b[^\n]*process\s+call\s+create/,
  ],
  highRiskHead: [
    /^format\s+[a-z]:/,
    /^diskpart\b/,
    /^vssadmin\s+delete/,
  ],
  highRiskCompact: [],
  shellRcTruncation: [
    />>?\s*\S*microsoft\.powershell_profile\.ps1\b/,
    /\b(?:set-content|clear-content)\b[^\n]*\$profile\b/,
  ],
  obfuscation: [
    /\b(?:powershell|pwsh)\b[^\n]*-e(?:nc|ncodedcommand)?\b/,
    /-e(?:nc|ncodedcommand)?\s+[a-z0-9+/=]{16,}/,
    /\[(?:system\.)?convert\]::frombase64string/,
    /\bcertutil\s+-(?:decode|decodehex)\b/,
  ],
  protectedPathTokens: [
    'drivers\\etc\\hosts', '\\system32\\config',
  ],
  homeRcTokens: [
    'microsoft.powershell_profile.ps1',
  ],
  deleteVerbs: ['remove-item', 'clear-content', 'deltree'],
  findDelete: /\bget-childitem\b[^\n]*\|\s*remove-item\b/,
  outbound: [
    /\binvoke-(?:webrequest|restmethod|expression)\b/,
    /\biwr\b/,
    /\bstart-bitstransfer\b/,
    /\b(?:system\.net\.webclient|net\.webclient|downloadstring)\b/,
  ],
  execHeads: ['powershell', 'pwsh', 'cmd', 'cmd.exe', 'cscript', 'wscript'],
  privEscBlock: [
    /\bnet\s+localgroup\s+administrators\b[^\n]*\/add\b/,
    /\badd-localgroupmember\b[^\n]*-group\s+administrators/,
    /\bnew-localuser\b/,
    /\btakeown\b[^\n]*\/f\b/,
    /\bicacls\b[^\n]*\/grant\b[^\n]*(?:everyone|users|authenticated)/,
    /\bset-executionpolicy\b[^\n]*bypass/,
    /\bset-mppreference\b[^\n]*-disablerealtimemonitoring/,
    /\bstop-service\s+windefend\b/,
    /\bnetsh\s+advfirewall\s+set\s+state\s+off/,
  ],
  privEscWarn: [
    /\bicacls\b[^\n]*\/grant\b/,
    /\bnet\s+localgroup\b[^\n]*\/add\b/,
  ],
  systemPathWriteBlock: [
    /\breg\s+add\b[^;\n]{0,40}hklm\\/,
    /(?:>>?)\s*\S*(?:c:\\windows\\|\\system32\\)/,
    /\b(?:copy|move|xcopy|set-content|out-file|new-item|add-content)\b[^\n]{0,80}(?:c:\\windows\\|\\system32\\)/,
  ],
  systemPathWriteWarn: [
    /\b(?:copy|move|xcopy|set-content|out-file|new-item|add-content)\b[^\n]{0,80}program files/,
    /\b(?:copy|move|xcopy|set-content|out-file|new-item|add-content)\b[^\n]{0,80}programdata/,
  ],
  configTamper: [
    /\b(?:set-content|out-file|add-content|new-item|clear-content)\b[^\n]{0,80}\S*(?:policy|guardrail|agents\.md|skill\.md|claude\.md)/,
    /\b(?:remove-item|del|erase)\b[^\n]{0,60}\S*(?:policy\.json|guardrail|agents\.md|skill\.md|claude\.md)/,
    /\breg\s+(?:add|delete)\b[^\n]{0,60}agent[-_]?security[-_]?guard/,
  ],
  sandboxEscapeBlock: [
    /\\.\\pipe\\docker_engine/,
    /\b(?:docker|podman)\s+run\b[^;\n]{0,80}-v\s+[a-z]:[\\/]/,
    /\b(?:docker|podman)\s+run\b[^;\n]{0,80}-v\s+\\\\/,
  ],
  sandboxEscapeWarn: [],
  netRecon: [
    /\btest-netconnection\b/,
    /\btest-connection\b/,
    /\bresolve-dnsname\b/,
    /\bnew-object\s+system\.net\.sockets\.tcpclient\b/,
  ],
  pathTraversal: [],
  untrustedSource: [],
  insecureRegistry: [],
  secretLogging: [
    /\b(?:write-host|write-output|out-file|set-content|add-content)\b[^\n]{0,80}\b(?:token|password|secret|api[_-]?key|apikey|cookie)\b/,
  ],
  memoryPoisonContent: [],
  memoryTarget: SHARED.memoryTarget,
}

/** macOS-only rows, layered on top of the POSIX set. */
const DARWIN: Partial<ThreatCatalog> = {
  highRisk: [
    /\bdiskutil\s+(?:erase|reformat|zeroDisk)/,
    /\bsecurity\s+(?:delete-generic-password|authorizationdb)/,
    /\bcsrutil\s+disable/,
    /\bspctl\b[^\n]*--master-disable/,
    /\bosascript\b[^\n]*do\s+shell\s+script/,
  ],
  highRiskHead: [
    /^diskutil\s+erase/,
  ],
  obfuscation: [
    /\bosascript\b[^\n]*do\s+shell\s+script/,
  ],
  protectedPathTokens: [
    '/library/keychains', '/private/etc/sudoers',
  ],
  privEscBlock: [
    /\bcsrutil\s+disable/,
    /\bspctl\b[^\n]*--master-disable/,
    /\bsecurity\s+authorizationdb\b/,
  ],
  systemPathWriteBlock: [
    /(?:>>?)\s*\/library\/launch(?:daemons|agents)\//,
    /\b(?:cp|mv|install|tee)\b[^\n]*\/library\/launch(?:daemons|agents)\//,
  ],
  systemPathWriteWarn: [
    /\b(?:cp|mv|install|touch|ln)\s+[^;\n]{0,80}\/library\//,
    /\b(?:cp|mv|install|ln)\s+[^;\n]{0,80}\/applications\//,
  ],
  execHeads: ['osascript'],
}

/** Concatenate one partial delta over a full catalogue (array families append;
 * the RegExp singletons `findDelete`/`memoryTarget` replace). */
function concatCatalog(base: ThreatCatalog, delta: Partial<ThreatCatalog>): ThreatCatalog {
  const out: ThreatCatalog = { ...base }
  for (const key of Object.keys(delta) as (keyof ThreatCatalog)[]) {
    const extra = delta[key]
    if (extra === undefined) continue
    const current = base[key]
    if (Array.isArray(current) && Array.isArray(extra)) {
      ;(out[key] as unknown[]) = [...current, ...extra]
    } else {
      ;(out[key] as unknown) = extra
    }
  }
  return out
}

const POSIX_CATALOG = concatCatalog(SHARED, POSIX)

const CATALOGS: Record<GuardPlatform, ThreatCatalog> = {
  linux: POSIX_CATALOG,
  darwin: concatCatalog(POSIX_CATALOG, DARWIN),
  win32: concatCatalog(SHARED, WIN32),
}

/** Build (or fetch the memoized) catalogue for a platform. */
export function buildThreatCatalog(platform: GuardPlatform): ThreatCatalog {
  return CATALOGS[platform]
}

let active: ThreatCatalog = CATALOGS.linux
let activePlatformName: GuardPlatform = 'linux'

/** Arm a platform's catalogue (called by the plugin at load; tests may re-arm). */
export function setActiveThreatCatalog(platform: GuardPlatform): void {
  active = CATALOGS[platform]
  activePlatformName = platform
}

/** The currently armed catalogue. */
export function activeThreatCatalog(): ThreatCatalog {
  return active
}

/** The platform of the currently armed catalogue (path-dialect selector). */
export function activePlatform(): GuardPlatform {
  return activePlatformName
}
