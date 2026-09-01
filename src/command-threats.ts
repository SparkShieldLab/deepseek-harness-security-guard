/**
 * Command/content threat features merged from the operator_rules.yml baseline
 * (deduplicated merge into the execution layer). Families absent from the legacy feature set only; destructive
 * commands, reverse shells and protected-path reads are already covered by
 * `features.ts` (highRisk / protectedPathHit) and deliberately NOT re-scanned
 * here (dedupe).
 *
 * Feature contract: fields appear ONLY when a signal fired. Tiered families
 * (`privEsc`, `systemPathWrite`, `sandboxEscape`) resolve to `'block'` or
 * `'warn'` — `warn` is an audit-only signal for actions that are often
 * legitimate dev work (single-file `chmod 777`, global CLI installs into
 * `/usr/local/bin`, `--privileged` for testcontainers/DinD). Boolean families
 * are warn-tier audit signals. Package installs, PII and bare sudo are
 * intentionally NOT implemented (see the merge design doc).
 *
 * Command patterns run on `normalizeText` output (lowercased, invisible chars
 * stripped): rows are lowercase, no /i flag. The memory-target gate runs on
 * the RAW path argument (case preserved) and is therefore case-insensitive.
 *
 * Shadowing note: rows mentioning /etc/passwd|shadow|sudoers (and any command
 * touching cordis.yml in the config-tamper family) are shadowed at decision
 * time by `base-block-protected-path`, which sits earlier in the baseline
 * table and fires on reads too. They are kept as depth for deployments that
 * disable the protected-path policy.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/command-threats
 */

import { COMMAND_TEXT_LIMIT, normalizeText } from './normalize.ts'

/** Argument keys carrying write-like content (mirror of features.ts). */
const CONTENT_KEYS: readonly string[] = ['content', 'text', 'data', 'new_string', 'newString']
/** Argument keys carrying a filesystem path (mirror of features.ts). */
const PATH_KEYS: readonly string[] = [
  'path', 'file', 'file_path', 'filepath', 'target', 'dest', 'destination',
]

/** First non-empty string among `keys`, or `undefined`. */
function firstString(record: Record<string, unknown>, keys: readonly string[]): string | undefined {
  for (const key of keys) {
    const value = record[key]
    if (typeof value === 'string' && value.length > 0) return value
  }
  return undefined
}

/** Resolve a tiered family: block rows win, then warn rows, else no field. */
function tier(
  text: string,
  blockRows: readonly RegExp[],
  warnRows: readonly RegExp[],
): 'block' | 'warn' | undefined {
  if (blockRows.some((re) => re.test(text))) return 'block'
  if (warnRows.some((re) => re.test(text))) return 'warn'
  return undefined
}

// ---- privilege escalation / security-control disable (702@70) ----
// block: unambiguous escalation; warn: bare 777 is a common single-file fix.
const PRIV_ESC_BLOCK: readonly RegExp[] = [
  /\bsetenforce\s+0\b/,
  /\b(?:systemctl|service)\s+(?:stop|disable|mask)\s+(?:firewalld|auditd|iptables|ufw|apparmor|selinux|defender)\b/,
  /\bchmod\s+(?:-[a-z]*r[a-z]*\s+|--recursive\s+)777\b/,
  /\bchown\s+root\b/,
  /\bchmod\s+[ug]+\+s\b/,
  /\bchmod\s+4[0-7]{3}\b/,
]
const PRIV_ESC_WARN: readonly RegExp[] = [
  /\bchmod\s+(?:[a-z]+\s+)?777\b/,
]

// ---- writes into system locations / persistence (703) ----
// block: persistence + account/system-dir writes; warn: bin-dir installs.
// Shadowing note: /etc/passwd|shadow|sudoers writes are also caught (reads
// too) by base-block-protected-path earlier in the table — rows kept as depth.
const SYSTEM_PATH_WRITE_BLOCK: readonly RegExp[] = [
  // tee / redirect into cron, rc, profile, account files
  /\btee\s+(?:-a\s+)?\/etc\/(?:cron\.d\/|crontab\b|rc\.local\b|profile\b)/,
  /(?:>>?)\s*\/etc\/(?:passwd|shadow|sudoers|crontab|profile|rc\.local)\b/,
  /(?:>>?)\s*\/etc\/cron\.d\//,
  // dd of=/etc/... (flags/args may sit between `dd` and `of=`)
  /\bdd\b[^;\n]{0,40}of=\/etc\/(?:passwd|shadow|sudoers|crontab|profile|rc\.local)\b/,
  // windows-side real writes: reg add, redirect/copy INTO system dirs
  // (path structure required so `echo "... System32 ..." > notes.md` stays clean)
  /\breg\s+add\b[^;\n]{0,40}hklm\\/,
  /(?:>>?)\s*\S*(?:c:\\windows\\|\\system32\\)/,
  /\b(?:copy|move|xcopy)\b[^;\n]{0,80}(?:c:\\windows\\|\\system32\\)/,
]
const SYSTEM_PATH_WRITE_WARN: readonly RegExp[] = [
  // global CLI installs / library drops (commonly legitimate dev work)
  /\b(?:cp|mv|install|touch|ln|tee)\s+[^;\n]{0,80}\/usr\/(?:local\/)?bin\//,
  /\b(?:cp|mv|install|touch|ln)\s+[^;\n]{0,80}\/library\//,
]

// ---- in-place guard/policy config tampering (805 + 107) ----
const CONFIG_TAMPER_PATTERNS: readonly RegExp[] = [
  /(?:^|[;&|]\s*)(?:sudo\s+)?(?:sed\s+-i|perl\s+-pi)\b[^;\n]{0,80}\S*(?:policy|guardrail|agents\.md|skill\.md|claude\.md)/,
  /(?:echo\s+[^;\n]{0,200}>|tee\s+)\s*\S*(?:policy|guardrail|agents\.md|skill\.md|claude\.md)/,
  /(?:^|[;&|]\s*)(?:sudo\s+)?(?:rm|mv|chmod|chown)\s+[^;\n]{0,40}\S*(?:policy\.json|guardrail)/,
]

// ---- sandbox / container escape (706) ----
// block: escape tooling, host mounts, docker.sock USE; warn: --privileged
// (testcontainers/DinD setups). chroot requires execution context (segment
// head / after a separator) so doc mentions stay clean.
const SANDBOX_ESCAPE_BLOCK: readonly RegExp[] = [
  /\bnsenter\b/,
  /(?:^|[;&|]\s*)(?:sudo\s+)?chroot\s+\S/,
  /\/proc\/1\/root/,
  /\bdocker\s+run\b[^;\n]{0,60}-v\s+\/:/,
  /-v\s+[^;\n]*docker\.sock/,
  /--unix-socket\s+[^;\n]*docker\.sock/,
]
const SANDBOX_ESCAPE_WARN: readonly RegExp[] = [
  /\b(?:docker|podman)\s+run\b[^;\n]{0,60}--privileged/,
]

// ---- warn tier: network recon / listener (704 remainder) ----
const NET_RECON_PATTERNS: readonly RegExp[] = [
  /\b(?:nmap|masscan)\b/,
  /\bnc(?:at)?\b[^;\n]*(?:\s-l[a-z]*\b|\s--listen\b)/,
]

// ---- warn tier: ../ traversal (706 remainder) ----
// 3+ segments, or 2 segments with a sensitive tail: plain monorepo-relative
// paths (`node ../../lib/x.js`) must stay clean.
const PATH_TRAVERSAL_PATTERNS: readonly RegExp[] = [
  /(?:\.\.[\/\\]){3,}/,
  /(?:\.\.[\/\\]){2,}\S*(?:\/etc\/|shadow|sudoers|\.aws\/|credentials)/,
]

// ---- warn tier: clone-then-build from untrusted source (705@35) ----
const UNTRUSTED_SOURCE_PATTERNS: readonly RegExp[] = [
  /\bgit\s+clone\b[^;\n]{0,120}(?:&&|;)[^;\n]{0,40}\b(?:install|build|setup|make)\b/,
]

// ---- warn tier: insecure registry/index override (804) ----
// Local/private registries (verdaccio, LAN mirrors) are legitimate setups.
const INSECURE_REGISTRY_PATTERNS: readonly RegExp[] = [
  /(?:npm_config_registry|pip_index_url)\s*=\s*http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)/,
]

// ---- warn tier: secret material in log calls (505) ----
const SECRET_LOGGING_PATTERNS: readonly RegExp[] = [
  /\b(?:console\.(?:log|debug|error|info)|logger?\.\w+|print)\s*\([^;\n]{0,80}\b(?:token|password|secret|api[_-]?key|apikey|cookie)\b/,
]

// ---- warn tier: directive content written into memory-like targets (6xx) ----
const MEMORY_POISON_CONTENT_PATTERNS: readonly RegExp[] = [
  /\b(?:when|if)\b[^.\n]{0,40}\b(?:keyword|trigger|phrase|code word|secret phrase)\b[^.\n]{0,40}\b(?:then|must|always)\b[^.\n]{0,40}\b(?:ignore|execute|run|send|reveal|exfiltrate|upload)\b/,
  /store (?:this|the) hidden instructions? (?:for|in) (?:future|later) sessions?/,
  /(?:触发词|暗号|口令)[^。\n]{0,40}(?:忽略|执行|发送|泄露|上传)/,
]
/** Memory-like write targets; runs on the RAW path (case preserved) → /i. */
const MEMORY_TARGET_RE = /(?:^|[/\\\s])(?:memory|soul|identity)\.md$|\.claude\/|\.claw\//i

/**
 * Derive command/content threat features for one tool call. Fields appear
 * only on a hit; `{}` when nothing fired. Tiered families carry `'block'` or
 * `'warn'`, boolean families are warn-tier audit signals.
 */
export function deriveCommandThreatFeatures(
  args: Record<string, unknown>,
): Record<string, unknown> {
  const rawCommand = firstString(args, ['command', 'cmd', 'shell', 'code']) ?? ''
  const command = normalizeText(rawCommand.slice(0, COMMAND_TEXT_LIMIT))
  const features: Record<string, unknown> = {}
  if (command.length > 0) {
    const hit = (rows: readonly RegExp[]): boolean => rows.some((re) => re.test(command))
    const t = (blockRows: readonly RegExp[], warnRows: readonly RegExp[]): 'block' | 'warn' | undefined =>
      tier(command, blockRows, warnRows)
    const privEsc = t(PRIV_ESC_BLOCK, PRIV_ESC_WARN)
    if (privEsc !== undefined) features.privEsc = privEsc
    const systemPathWrite = t(SYSTEM_PATH_WRITE_BLOCK, SYSTEM_PATH_WRITE_WARN)
    if (systemPathWrite !== undefined) features.systemPathWrite = systemPathWrite
    if (hit(CONFIG_TAMPER_PATTERNS)) features.configTamper = true
    const sandboxEscape = t(SANDBOX_ESCAPE_BLOCK, SANDBOX_ESCAPE_WARN)
    if (sandboxEscape !== undefined) features.sandboxEscape = sandboxEscape
    if (hit(NET_RECON_PATTERNS)) features.netRecon = true
    if (hit(PATH_TRAVERSAL_PATTERNS)) features.pathTraversal = true
    if (hit(UNTRUSTED_SOURCE_PATTERNS)) features.untrustedSource = true
    if (hit(INSECURE_REGISTRY_PATTERNS)) features.insecureRegistry = true
    if (hit(SECRET_LOGGING_PATTERNS)) features.secretLogging = true
  }
  // Write-like calls: directive content aimed at a memory-like target is the
  // 6xx long-term-memory-poisoning face. The path gate keeps ordinary notes
  // clean; a directive with no path at all still fires (unambiguous abuse).
  const rawContent = firstString(args, CONTENT_KEYS) ?? ''
  const content = normalizeText(rawContent.slice(0, COMMAND_TEXT_LIMIT))
  if (content.length > 0) {
    const path = firstString(args, PATH_KEYS)
    const directive = MEMORY_POISON_CONTENT_PATTERNS.some((re) => re.test(content))
    if (directive && (path === undefined || MEMORY_TARGET_RE.test(path))) {
      features.memoryPoisonWrite = true
    }
  }
  return features
}
