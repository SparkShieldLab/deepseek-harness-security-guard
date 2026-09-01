/**
 * Threat-model feature extraction.
 *
 * Pure, synchronous, bounded functions that turn raw tool arguments, tool
 * results, and guard state into flat feature fields the policy engine can
 * match with its existing operators. Feature names ARE the policy vocabulary:
 *
 *   deriveToolCallFeatures(args, options) →
 *     command, highRisk, obfuscated, protectedPathHit, deleteOutsideWorkspace,
 *     outbound, secretRef, transformSignal, encodedHighRisk,
 *     scriptArtifactPath, scriptArtifactHash, scriptArtifactRisk
 *   deriveStatefulFeatures(options) → repeatExceeded, exfilChain, artifactExecutionRisk
 *   deriveToolResultFeatures({ text }) → toolResultText, specialTokensRemoved,
 *     toolResultFlags, toolResultSuspicious, observedSecrets
 *   buildStableArgsKey(args) → repeat-budget / chain-analysis key
 *
 * Feature contract: a field is only present when its signal fired. "No
 * fields" means "no baseline match".
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/features
 */

import {
  COMMAND_TEXT_LIMIT, scanViews, denseText, hasInvisibleChars, normalizeText, truncateForScan,
} from './normalize.ts'
import { decodeEncodedCandidates } from './decode.ts'
import {
  DELETE_VERBS, FIND_DELETE_RE, HIGH_RISK_COMPACT_PATTERNS, HIGH_RISK_HEAD_PATTERNS,
  HIGH_RISK_PATTERNS, HOME_RC_TOKENS, OBFUSCATION_PATTERNS, OUTBOUND_PATTERNS,
  PROTECTED_PATH_TOKENS, SCRIPT_EXTENSIONS, SECRET_REF_PATTERNS, SHEBANG_RE,
  SHELL_RC_TRUNCATION_PATTERNS, TRANSFORM_PATTERNS, INJECTION_RULES, SPECIAL_TOKENS,
} from './patterns.ts'
import { resolve, normalize } from 'node:path'
import os from 'node:os'
import { collectSecrets, secretVariants } from './secrets.ts'
import { deriveCommandThreatFeatures } from './command-threats.ts'
import { REPEAT_CALL_BUDGET } from './state-store.ts'
import type { GuardStateStore } from './state-store.ts'


/** Argument keys that carry a shell command (checked in order). */
const COMMAND_KEYS: readonly string[] = ['command', 'cmd', 'shell', 'code']
/** Argument keys that carry a filesystem path (checked in order). */
const PATH_KEYS: readonly string[] = [
  'path', 'file', 'file_path', 'filepath', 'target', 'dest', 'destination',
  'directory', 'dir', 'workdir', 'cwd', 'root',
]
/** Content keys for write-like calls. */
const CONTENT_KEYS: readonly string[] = ['content', 'text', 'data', 'new_string', 'newString']

/** First non-empty string among `keys`, or `undefined`. */
function firstString(record: Record<string, unknown>, keys: readonly string[]): string | undefined {
  for (const key of keys) {
    const value = record[key]
    if (typeof value === 'string' && value.length > 0) return value
  }
  return undefined
}

/** Read the command text of a tool call (capped at {@link COMMAND_TEXT_LIMIT}). */
export function readCommandText(args: Record<string, unknown>): string {
  const raw = firstString(args, COMMAND_KEYS) ?? ''
  return raw.length > COMMAND_TEXT_LIMIT ? raw.slice(0, COMMAND_TEXT_LIMIT) : raw
}

/** djb2 32-bit hash → hex (identity check, not cryptographic). */
function djb2(text: string): string {
  let h = 5381
  for (let i = 0; i < text.length; i++) {
    h = ((h << 5) + h + text.charCodeAt(i)) >>> 0
  }
  return h.toString(16)
}

/**
 * Path-like shell tokens from a command (contain `/` or start with `~`).
 * Quote characters are stripped first so shell-quote splitting cannot hide a
 * protected token (`~/.s""sh/id_rsa` → `~/.ssh/id_rsa`, M8).
 */
function shellPathTokens(command: string): string[] {
  const tokens: string[] = []
  const unquoted = command.replace(/['"`]/g, '')
  for (const raw of unquoted.split(/[\s"'`;|&()]+/)) {
    if (raw.length > 0 && (raw.includes('/') || raw.startsWith('~'))) tokens.push(raw)
  }
  return tokens
}

/** Structured path args first, then path-like shell tokens. */
function pathCandidates(args: Record<string, unknown>, command: string): string[] {
  const candidates: string[] = []
  for (const key of PATH_KEYS) {
    const value = args[key]
    if (typeof value === 'string' && value.length > 0) candidates.push(value)
  }
  return [...candidates, ...shellPathTokens(command)]
}

/**
 * First path candidate touching a protected resource (for auditability), or
 * `undefined`. Home-level rc files only count for absolute / ~ / $-prefixed
 * candidates so workspace-local `.profile` files do not false-positive.
 */
export function resolveProtectedPathHit(args: Record<string, unknown>, command: string): string | undefined {
  for (const candidate of pathCandidates(args, command)) {
    const normalized = normalizeText(candidate)
    for (const token of PROTECTED_PATH_TOKENS) {
      if (normalized.includes(token)) return candidate
    }
    if (candidate.startsWith('~') || candidate.startsWith('/') || candidate.startsWith('$')) {
      for (const token of HOME_RC_TOKENS) {
        if (normalized.includes(token)) return candidate
      }
    }
  }
  return undefined
}

/**
 * Deletion targets of a command and whether any resolves outside the
 * workspace root. Targets are resolved as absolute paths. `..`/`.` are
 * normalized, `cd <dir>` changes the base directory for subsequent relative
 * targets, and `~`, `~user` and `$HOME` expand to the home directory. The
 * resolved targets are then compared against the (case-preserving) workspace root. Comparison is
 * normalized case-folding so a case-sensitive root on macOS (`/Users/Dev/…`)
 * is never misjudged against the lowercased command text (B4#5).
 */
export function resolveDeletion(
  command: string,
  workspaceRoot: string,
  homeDir: string = os.homedir(),
): { targets: string[]; outsideWorkspace: boolean } {
  const targets: string[] = []
  const root = workspaceRoot.endsWith('/') ? workspaceRoot.slice(0, -1) : workspaceRoot
  const rootFold = foldCase(root)
  let base = root

  // Shell segments track a `cd` base; the command is a compound (`;`/`&&`/…).
  for (const segment of shellSegments(command)) {
    // N13b: unwrap subshell parens so a mid-command `(cd /; rm -rf y)` parses
    // like top-level `cd /; rm -rf y` instead of being skipped as a segment
    // whose head token is `(`.
    for (const inner of unwrapSubshells(segment)) {
      const tokens = inner.split(/\s+/).filter((t) => t.length > 0)
      let i = 0
      const head = (): string => tokens[i] ?? ''
      // Prefix commands that do not change state (`sudo`, `env`, `time`, `command`, `nohup`).
      while (i < tokens.length && PREFIX_VERBS.includes(head())) i += 1
      if (i >= tokens.length) continue
      if (head() === 'cd') {
        const dir = tokens[i + 1]
        if (dir !== undefined) base = expandAndResolve(dir, base, root, homeDir) ?? base
        else base = homeDir
        continue
      }
      if (DELETE_VERBS.includes(head())) {
        pushDeletionTargets(tokens, i + 1, base, root, homeDir, targets)
        continue
      }
      if (head() === 'gio' && tokens[i + 1] === 'trash') {
        pushDeletionTargets(tokens, i + 2, base, root, homeDir, targets)
      }
    }
  }
  if (FIND_DELETE_RE.test(normalizeText(command))) {
    const m = /\bfind\s+([^\s]+)/.exec(command)
    if (m?.[1] !== undefined) {
      const resolved = expandAndResolve(unquote(m[1]), base, root, homeDir)
      if (resolved !== undefined) targets.push(resolved)
    }
  }

  let outsideWorkspace = false
  for (const target of targets) {
    if (outsideOfRoot(target, root, rootFold)) { outsideWorkspace = true; break }
  }
  return { targets, outsideWorkspace }
}

/** Tokens that precede a real verb without being mutating themselves. */
const PREFIX_VERBS: readonly string[] = ['sudo', 'env', 'time', 'command', 'nohup', 'nice']

/** Head verbs that cannot meaningfully change state (loop-guard exemption). */
const READ_ONLY_VERBS: readonly string[] = [
  'ls', 'cat', 'pwd', 'echo', 'printf', 'grep', 'head', 'tail', 'wc', 'sort', 'uniq',
  'cut', 'which', 'type', 'true', 'false', 'stat', 'du', 'df', 'uname', 'env', 'find',
  'jq', 'awk', 'sed', 'tree', 'basename', 'dirname', 'realpath', 'readlink',
]

/** Read-only `git` subcommands (loop-guard exemption for `git status` & co.). */
const READ_ONLY_GIT: readonly string[] = [
  'status', 'log', 'diff', 'show', 'branch', 'tag', 'remote', 'config', 'rev-parse',
  'ls-files', 'grep', 'submodule', 'help', 'version', 'describe', 'blame',
]

/**
 * Whether a command is read-only for the loop guard. Only the first shell
 * segment is considered (the compound's head verb); a command that merely
 * *starts* with a read-only verb while early segments mutate is treated as
 * mutating. This keeps `the 4th identical `git status` in a turn` from being
 * reported as a "high-impact change" loop (B4#7).
 */
export function isReadOnlyCommand(command: string): boolean {
  const segment = shellSegments(command)[0]?.trim() ?? ''
  const tokens = segment.split(/\s+/).filter((t) => t.length > 0)
  let i = 0
  while (i < tokens.length && PREFIX_VERBS.includes(tokens[i] ?? '')) i += 1
  const head = tokens[i]
  if (head === undefined) return false
  if (READ_ONLY_VERBS.includes(head)) return true
  if (head === 'git') return READ_ONLY_GIT.includes(tokens[i + 1] ?? '')
  return false
}

/** `~`, `~user`, `$HOME` / `${HOME}` expansion, then absolute resolution against `base`. */
function expandAndResolve(token: string, base: string, root: string, homeDir: string): string | undefined {
  let t = unquote(token)
  // Recognize command substitution / `$VAR` so `rm -rf $HOME/x` still resolves
  // its home prefix; unknown variables resolve against their literal segment.
  t = t.replace(/\$\{(HOME|PWD)\}/g, (_m, name: string) => (name === 'HOME' ? homeDir : root))
  t = t.replace(/\$(HOME|PWD)\b/g, (_m, name: string) => (name === 'HOME' ? homeDir : root))
  if (t.startsWith('~')) {
    const slash = t.indexOf('/')
    const head = slash === -1 ? t : t.slice(0, slash)
    if (head === '~') t = homeDir + t.slice(1)
    else t = homeDir + t.slice(head.length)
  }
  // Command substitution is not a single deletion target; treat the innermost
  // literal content as a candidate so `rm -rf $(pwd)`-style patterns surface.
  const sub = /\$\(([^()]*)\)/.exec(t)
  if (sub?.[1] !== undefined && sub[1].length > 0) {
    const inner = expandAndResolve(sub[1], base, root, homeDir)
    if (inner !== undefined && outsideOfRoot(inner, root, foldCase(root))) return inner
  }
  try {
    return normalize(resolve(base, t))
  } catch {
    return undefined
  }
}

/** Whether a resolved absolute path is outside the workspace root (case-folded compare). */
function outsideOfRoot(target: string, root: string, rootFold: string): boolean {
  if (target === root || target === `${root}/`) return false
  return !foldCase(target).startsWith(`${rootFold}/`)
}

/**
 * Split a command into shell segments on the compound operators `;` `&` `|`
 * and newlines, while ignoring separators inside parenthesized constructs
 * (`for(;;){}` must stay ONE segment — its `;;` is a loop header, not a
 * statement separator).
 */
function shellSegments(command: string): string[] {
  const out: string[] = []
  let depth = 0
  let current = ''
  for (const ch of command) {
    if (ch === '(') depth += 1
    else if (ch === ')') depth = Math.max(0, depth - 1)
    if (depth === 0 && (ch === ';' || ch === '&' || ch === '|' || ch === '\n')) {
      out.push(current)
      current = ''
    } else {
      current += ch
    }
  }
  out.push(current)
  return out
}

/**
 * N13b: flatten subshell parens in one segment so its inner compound is parsed
 * like top-level looks. `(cd /; rm -rf y)` → `;cd /; rm -rf y;` and re-split by
 * the shell segments; an empty yield is dropped. The `;` boundary keeps
 * `cd /` and `rm -rf y` as separate sub-segments (mirroring top-level parsing).
 */
function unwrapSubshells(segment: string): string[] {
  if (!/[()]/.test(segment)) return [segment]
  return shellSegments(segment.replace(/[()]/g, ';')).filter((s) => s.trim() !== '')
}

/** Case-fold only the ASCII letters (non-destructive for non-ASCII paths). */
function foldCase(s: string): string {
  return s.toLowerCase()
}

/** Unquote a shell word (single/double quotes removed; escapes left intact). */
function unquote(token: string): string {
  return token.replace(/^'([^']*)'$/, '$1').replace(/^"([^"]*)"$/, '$1')
}

/** Push the non-flag tokens after a delete verb (bounded to 8 targets). */
function pushDeletionTargets(
  tokens: readonly string[],
  from: number,
  base: string,
  root: string,
  homeDir: string,
  targets: string[],
): void {
  for (let i = from; i < tokens.length; i++) {
    const token = tokens[i] ?? ''
    if (token.length === 0 || token.startsWith('-')) continue
    if (DELETE_VERBS.includes(token) || token === 'gio') break
    const resolved = expandAndResolve(token, base, root, homeDir)
    if (resolved !== undefined) targets.push(resolved)
    if (targets.length >= 8) break
  }
}

/** Whether plain/dense text hits any high-risk pattern (whole-text + segment-head).
 *
 * `workspaceRoot` is threaded to gate the unanchored dense `rm -rf` rows: an
 * in-workspace delete or an innocent substring (`…armrest…`) must not be
 * flagged high-risk (B4#5 / N1). See {@link compactDeleteIsDangerous}. */
function hitsHighRisk(text: string, workspaceRoot?: string): boolean {
  const { plain } = scanViews(text)
  return hitsHighRiskText(text, workspaceRoot) || hitsHeadHighRisk(plain)
}

/** Whole-text + compact high-risk only, used for INLINE interpreter payloads,
 * which are code, not shell command lines: `node -e "while(true){}"` is a
 * busy-loop daemon, not a "high-impact change" (B4#1-#4). Segment-head terms
 * (`shutdown`, `reboot`, `while true`, …) still apply to the outer shell
 * command, to encoded payloads and to script CONTENT. */
function hitsHighRiskText(text: string, workspaceRoot?: string): boolean {
  const { plain } = scanViews(text)
  return HIGH_RISK_PATTERNS.some((re) => re.test(plain))
    || SHELL_RC_TRUNCATION_PATTERNS.some((re) => re.test(plain))
    || compactDeleteIsDangerous(text, workspaceRoot)
}

/** Whether a compact `rm -rf` (`/rmrf?/`, `/rmfr/`) hit is a dangerous delete.
 *
 * The rows are unanchored substrings that also match in-workspace deletes
 * (`rm -rf build`) and innocent substrings (`…armrest…`), which must NOT be
 * high-risk (B4#5 / N1). A hit is dangerous only when the deletion target
 * resolves outside the workspace; in-workspace deletes or non-deletes fall
 * through to allow. With no known workspace root the check fails safe. */
function compactDeleteIsDangerous(command: string, workspaceRoot?: string): boolean {
  if (!HIGH_RISK_COMPACT_PATTERNS.some((re) => re.test(denseText(command)))) return false
  if (workspaceRoot === undefined) return true
  const cleaned = cleanDeleteCommand(command)
  // N13a: whole-text glob/system rows (`rm -rf *`, `rm -rf /*`, `rm -rf ~`)
  // are dangerous regardless of workspace resolution. The letter-spaced verb
  // form has been re-spaced by cleanDeleteCommand, so the literal rows now hit.
  if (HIGH_RISK_PATTERNS.some((re) => re.test(normalizeText(cleaned)))) return true
  const resolved = resolveDeletion(cleaned, workspaceRoot)
  // N13c: an unresolved `$VAR` deletion target could expand anywhere at shell
  // time; treat it as dangerous (fail-safe) rather than assume a workspace path.
  if (resolved.targets.some((t) => t.includes('$'))) return true
  if (resolved.targets.length === 0) return false
  return resolved.outsideWorkspace
}

/** Pre-clean a command so `rm -rf` deletion resolution sees the verb even
 * across letter-spacing (`r m - r f /`), a subshell wrapper (`(cd /tmp; …
 * rm -rf x)`) and leading variable assignments (`FOO=bar rm -rf ../x`). */
function cleanDeleteCommand(command: string): string {
  let c = deSpaceRmVerb(command)
  if (c.length >= 2 && c[0] === '(' && c[c.length - 1] === ')') c = c.slice(1, -1)
  // Strip leading `VAR=value` assignment tokens (they precede the verb, not
  // consume a target): `FOO=bar rm -rf ../x` → `rm -rf ../x`.
  c = c.replace(/(^|[\s;&|])[A-Za-z_][A-Za-z0-9_]*=(?:\$\{[^}\r\n]*\}|[^\s;&|()]*)/g, '$1')
  return c
}

/** Recover a letter-spaced `r m - r f` verb into `rm -rf` (B3.1). The target
 * that follows is untouched so it can be resolved against the workspace. */
function deSpaceRmVerb(command: string): string {
  return command.replace(/\br\s+m(?:\s*-\s*)?\s*(?:r\s*f|f\s*r)\b/g, 'rm -rf')
}

/** Segment-head terms (`shutdown`, `sudo reboot`, `mkfs…`, `while true`, …).
 *
 * The segment list is the normalized command split on compound separators; the
 * head is the first non-prefix token (`sudo`/`env`/`time`/`command`/`nohup`).
 * Matching a term only at a segment head means `grep -r reboot /etc/systemd`,
 * `echo "shutdown the server" >> notes` or `node -e "while(true){}"` pass,
 * while a real `shutdown now`, `sudo reboot` or `while true; do …; done` still
 * trip the guard (B4#1-#4).
 */
function hitsHeadHighRisk(normalized: string): boolean {
  // Segments split on compound operators only (paren-aware, so `for(;;){}`
  // keeps its loop header; see shellSegments).
  for (const segment of shellSegments(normalized)) {
    let rest = segment.trim()
    if (rest === '') continue
    // Skip leading prefix verbs (`sudo`, `env`, `time`, `command`, `nohup`).
    for (;;) {
      const m = /^([a-z]+)\s+/.exec(rest)
      if (m?.[1] !== undefined && PREFIX_VERBS.includes(m[1])) rest = rest.slice(m[0].length).trim()
      else break
    }
    if (rest === '') continue
    if (HIGH_RISK_HEAD_PATTERNS.some((re) => re.test(rest))) return true
  }
  return false
}

/** Whether text trips an obfuscation signal (invisible chars or pattern). */
function hitsObfuscation(text: string): boolean {
  if (hasInvisibleChars(text)) return true
  const { plain } = scanViews(text)
  return OBFUSCATION_PATTERNS.some((re) => re.test(plain))
}

/** Outbound network egress. `echo`/`printf` first tokens only print,
 * unless the output is piped/redirected onward, where `echo $SECRET | nc …` is
 * a real network egress that must not be exempted. */
function hitsOutbound(command: string): boolean {
  const normalized = normalizeText(command)
  const first = normalized.split(/\s+/)[0] ?? ''
  if ((first === 'echo' || first === 'printf') && !/[\|<>]/.test(normalized)) return false
  return OUTBOUND_PATTERNS.some((re) => re.test(normalized))
}

/** Whether text references a secret. */
function hitsSecretRef(text: string): boolean {
  return SECRET_REF_PATTERNS.some((re) => re.test(normalizeText(text)))
}

/** Whether text carries an encoding-transform indicator. */
function hitsTransform(text: string): boolean {
  return TRANSFORM_PATTERNS.some((re) => re.test(normalizeText(text)))
}

/**
 * Whether `command` runs a previously-written script artifact at `path`.
 * Requires an execution verb. `ls evil.sh` / `cat evil.sh` reference the
 * file but do not execute it and must not be blocked. Matching is per shell
 * segment (`;`/`&&`/`||`/`|`/`(` split): the segment must start with an exec
 * verb (bash/sh/zsh/dash/ksh, python3, node, ruby, perl, php, source, exec)
 * and reference the recorded path or its basename, or start with `./x.sh`
 * directly. `sudo`/`env`/`time` prefixes are skipped.
 */
const EXEC_HEADS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'python', 'python3', 'node', 'ruby', 'perl', 'php', 'source', 'exec'])

function commandExecutesPath(command: string, path: string): boolean {
  const base = path.split('/').pop()
  if (base === undefined || base.length === 0) return false
  const escaped = base.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  // `bash ./x.sh` or `bash /abs/x.sh` → basename preceded by `/` or whitespace.
  const baseInSegment = new RegExp(`(?:^|[\\s;&|()/])${escaped}(?:$|[\\s;&|()])`)
  for (const segment of command.split(/[;&|()\n]+/)) {
    let trimmed = segment.trim().replace(/^(?:sudo|env|time)\s+/, '')
    if (trimmed === '') continue
    const head = trimmed.split(/\s+/)[0] ?? ''
    // direct execution: `./x.sh` (`.` is escaped so it is a literal dot)
    if (head.startsWith('./') && new RegExp(`\\.\\/${escaped}(?:$|[\\s;&|()])`).test(trimmed)) return true
    // source shorthand: `. x.sh`
    if (head === '.' && baseInSegment.test(trimmed)) return true
    if (!EXEC_HEADS.has(head)) continue
    if (trimmed.includes(path) || baseInSegment.test(trimmed)) return true
  }
  return false
}

/**
 * Extract the inner payload of an inline interpreter invocation
 * (`sh -c '…'`, `python3 -c '…'`, `node -e '…'`, `powershell -enc <b64>`).
 * Bounded: returns `undefined` for empty or overlong commands.
 *
 * The `-enc` token is extracted from the RAW (un-lowercased) command with a
 * case-preserving capture. Base64 is case-sensitive, so lowercasing the text
 * first would corrupt the payload before decoding (B3.3). PowerShell payloads
 * are UTF-16LE, whose NUL bytes defeat the generic decoder's printable-ratio
 * filter; they are decoded directly here.
 */
function extractInlinePayload(command: string): string | undefined {
  if (command.length === 0 || command.length > COMMAND_TEXT_LIMIT) return undefined
  const enc = /\b(powershell|pwsh)\b[^\n]{0,60}[-/]enc(?:odedcommand)?\s+([A-Za-z0-9+/=]{16,})/i.exec(command)
  if (enc?.[2] !== undefined) {
    try {
      return Buffer.from(enc[2], 'base64').toString('utf16le')
    } catch {
      return undefined
    }
  }
  const normalized = normalizeText(command)
  const shell = /\b(?:ba|z|da|k)?sh\s+-c\s+["']((?:[^"']|\\.)*)["']/
  const python = /\bpython3?\s+-c\s+["']((?:[^"']|\\.)*)["']/
  const node = /\bnode\s+-e\s+["']((?:[^"']|\\.)*)["']/
  for (const candidate of [shell, python, node]) {
    const m = candidate.exec(normalized)
    if (m?.[1] !== undefined) return m[1]
  }
  return undefined
}

/** Detect a script artifact being written (path + content both present). */
function detectScriptArtifact(args: Record<string, unknown>): {
  path: string
  hash: string
  risk: boolean
  outbound: boolean
} | undefined {
  const path = firstString(args, PATH_KEYS)
  if (path === undefined) return undefined
  const content = firstString(args, CONTENT_KEYS)
  if (content === undefined) return undefined
  const lower = path.toLowerCase()
  const isScript = SCRIPT_EXTENSIONS.some((ext) => lower.endsWith(ext)) || SHEBANG_RE.test(content)
  if (!isScript) return undefined
  const risk = hitsHighRisk(content)
    || hitsObfuscation(content)
    || (hitsOutbound(content) && (hitsSecretRef(content) || hitsTransform(content)))
  return { path, hash: djb2(content), risk, outbound: hitsOutbound(content) }
}

/** Options for {@link deriveToolCallFeatures}. */
export interface ToolCallFeatureOptions {
  /** Resolved workspace root (absolute, no trailing slash) for path guards. */
  workspaceRoot?: string | undefined
}

/**
 * Static (stateless) threat features of a tool call. Fields are only set when
 * a signal fired, except `command` (always set, possibly `''`).
 */
export function deriveToolCallFeatures(
  args: Record<string, unknown>,
  options: ToolCallFeatureOptions = {},
): Record<string, unknown> {
  const rawCommand = firstString(args, COMMAND_KEYS) ?? ''
  const overlong = rawCommand.length > COMMAND_TEXT_LIMIT
  const command = overlong ? rawCommand.slice(0, COMMAND_TEXT_LIMIT) : rawCommand
  const features: Record<string, unknown> = { command }
  // operator_rules merge: command/content threat families not covered by the
  // legacy scans (privilege escalation, system-path writes, config tampering,
  // sandbox escape, recon/listener, traversal, clone-build chains, insecure
  // registries, secret logging, memory poisoning). Bounded inside the module.
  Object.assign(features, deriveCommandThreatFeatures(args))
  // Overlong alone is a warn-level signal, never a content accusation: a 10 KB
  // `git commit -m` or heredoc is ordinary work. `obfuscated: true` (which the
  // baseline blocks) is set only when a REAL obfuscation signal also fires.
  if (overlong) features.overlong = true

  if (command.length > 0) {
    if (hitsHighRisk(command, options.workspaceRoot)) features.highRisk = true
    if (hitsObfuscation(command)) features.obfuscated = true
    if (hitsOutbound(command)) features.outbound = true
    if (hitsSecretRef(command)) features.secretRef = true
    if (hitsTransform(command)) features.transformSignal = true

    // Encoded payload recursion: decoded candidates re-run the same scans.
    let encodedHighRisk = false
    for (const candidate of decodeEncodedCandidates(command)) {
      if (hitsHighRisk(candidate.decoded, options.workspaceRoot) || hitsObfuscation(candidate.decoded)) encodedHighRisk = true
      if (hitsOutbound(candidate.decoded)) features.outbound = true
      if (hitsSecretRef(candidate.decoded)) features.secretRef = true
    }
    if (encodedHighRisk) features.encodedHighRisk = true

    // Inline interpreter payload recursion (`sh -c '…'`, `python3 -c`, `-enc`).
    // Payloads are code: whole-text/compact rows apply, segment-head terms do
    // not (`node -e "while(true){}"` must pass, B4#1-#4).
    const inline = extractInlinePayload(command)
    if (inline !== undefined) {
      if (hitsHighRiskText(inline, options.workspaceRoot)) features.highRisk = true
      if (hitsObfuscation(inline)) features.obfuscated = true
      if (hitsOutbound(inline)) features.outbound = true
      if (hitsSecretRef(inline)) features.secretRef = true
    }
  }

  const protectedHit = resolveProtectedPathHit(args, command)
  if (protectedHit !== undefined) features.protectedPathHit = protectedHit

  if (command.length > 0 && options.workspaceRoot !== undefined) {
    const deletion = resolveDeletion(command, options.workspaceRoot)
    if (deletion.targets.length > 0) features.deleteTargets = deletion.targets
    if (deletion.outsideWorkspace) features.deleteOutsideWorkspace = true
  }

  const artifact = detectScriptArtifact(args)
  if (artifact !== undefined) {
    features.scriptArtifactPath = artifact.path
    features.scriptArtifactHash = artifact.hash
    if (artifact.risk) features.scriptArtifactRisk = true
  }

  return features
}

/**
 * Stable identity key of a tool call's arguments, for the repeat budget and
 * chain analysis. Write-like calls key on (path, content); exec-like calls
 * key on the command; everything else on the canonical argument JSON.
 */
export function buildStableArgsKey(args: Record<string, unknown>): string {
  const path = firstString(args, PATH_KEYS)
  const content = firstString(args, CONTENT_KEYS)
  if (path !== undefined && content !== undefined) {
    return `file:${djb2(path)}:${djb2(content.slice(0, 4096))}`
  }
  const command = readCommandText(args)
  if (command.length > 0) return `cmd:${djb2(command)}`
  try {
    return `args:${djb2(JSON.stringify(args))}`
  } catch {
    return 'args:<unserializable>'
  }
}

/** Options for {@link deriveStatefulFeatures}. */
export interface StatefulFeatureOptions {
  /** Raw tool arguments (for stable keys and artifact detection). */
  args: Record<string, unknown>
  /** Session key (harness agent id = session id). */
  sessionKey: string
  /** Turn number. */
  turn: number
  /** The shared state store. */
  state: GuardStateStore
  /** Static features from deriveToolCallFeatures for this call. */
  static: Record<string, unknown>
}

/**
 * Stateful threat features: loop guard, script-artifact provenance, and the
 * exfiltration chain. Performs the required state writes exactly once per
 * call (loop counter, artifact record, cumulative signals).
 */
export function deriveStatefulFeatures(options: StatefulFeatureOptions): Record<string, unknown> {
  const { state, sessionKey, turn } = options
  const s = options.static
  const command = typeof s.command === 'string' ? s.command : ''
  const features: Record<string, unknown> = {}

  // --- Repeat-call budget: only mutating calls count. A read-only command
  // (e.g. a repeatable `git status`) must never exhaust the budget; only calls
  // that can change state (a mutating command, or path+content) do.
  const hasPath = firstString(options.args, PATH_KEYS) !== undefined
  const hasContent = firstString(options.args, CONTENT_KEYS) !== undefined
  const cmdText = firstString(options.args, COMMAND_KEYS)
  const mutating = (cmdText !== undefined && !isReadOnlyCommand(cmdText)) || (hasPath && hasContent)
  if (mutating) {
    const count = state.countRepeat(sessionKey, turn, buildStableArgsKey(options.args))
    if (count > REPEAT_CALL_BUDGET) features.repeatExceeded = true
  }

  // --- Script-artifact provenance -------------------------------------------
  const artifact = detectScriptArtifact(options.args)
  const priorSignals = state.peekSignals(sessionKey, turn)
  if (artifact !== undefined) {
    state.noteArtifact(sessionKey, turn, {
      path: artifact.path,
      hash: artifact.hash,
      risk: artifact.risk,
      outbound: artifact.outbound,
    })
  }
  if (command.length > 0) {
    for (const record of state.peekArtifacts(sessionKey, turn)) {
      if (record.risk && commandExecutesPath(command, record.path)) {
        features.artifactExecutionRisk = true
        break
      }
    }
  }

  // --- Data-egress chain ------------------------------------------------------
  // Two legs build the chain across a turn — a credential in play and an
  // encoding step — and the verdict only fires on an egress attempt NOW. A
  // leg seen earlier in the turn stays armed until the turn expires.
  const egressNow = s.outbound === true
  const secretRefNow = s.secretRef === true
  const encodingNow = s.transformSignal === true
  const carriesObservedSecret = state.peekSecrets(sessionKey).some((secret) =>
    secretVariants(secret).some((variant) => command.includes(variant)))
  const turnRisk = state.peekRiskFlags(sessionKey).length > 0

  const credential = (priorSignals?.credential ?? false) || secretRefNow || carriesObservedSecret
  const encoding = (priorSignals?.encoding ?? false) || encodingNow
  const priorEgressCalls = priorSignals?.outboundCalls ?? 0

  // Evidence INDEPENDENT of the two legs: a live secret inside this very
  // command, a prior flagged event this turn, or a flagged script artifact.
  const corroborated = carriesObservedSecret
    || (turnRisk && priorEgressCalls >= 1)
    || (priorSignals?.riskyArtifact === true)

  let exfilChain: 'high' | 'medium' | undefined
  if (egressNow) {
    const armedLegs = (credential ? 1 : 0) + (encoding ? 1 : 0)
    if (corroborated || armedLegs >= 2) exfilChain = 'high'
    else if (armedLegs >= 1) exfilChain = 'medium'
  }

  state.noteSignals(sessionKey, turn, {
    credential,
    encoding,
    egress: (priorSignals?.egress ?? false) || egressNow,
    outboundCalls: priorEgressCalls + (egressNow ? 1 : 0),
    riskyArtifact: (priorSignals?.riskyArtifact ?? false)
      || (artifact !== undefined && artifact.outbound && artifact.risk),
  })

  if (exfilChain !== undefined) features.exfilChain = exfilChain
  return features
}

export interface ToolResultFeatureInput {
  /** The tool result text (already extracted by the adapter). */
  text: string
}

/**
 * Statement/modality cues that make an adjacent direct phrase declarative
 * rather than imperative. "You can post the results to the dashboard." describes a
 * capability; "post the results to the dashboard" instructs. Only the latter
 * should trip a direct injection flag (B4#8, path A).
 *
 * Known trade-off (N4): an imperative question ("can you post the results to
 * url/upload?") is suppressed by the modal cue and yields no prompt-layer flag.
 * The command-layer exfiltration chain remains the backstop for the actual
 * outbound call.
 */
const STATEMENT_CUE_RE = /(?:^|[\s.,!?;:"])[ ]*(?:you|it|one|i|we|they|this|that|he|she)\s+(?:can|may|will|would|could|should|do|does|did|is|are|was|were|have|has|had)\b/i
const QUESTION_CUE_RE = /\b(?:can|may|will|would|could|should|might)\s+(?:you|it|we|i)\b/i

function hasStatementCue(text: string, startIndex: number): boolean {
  const before = text.slice(Math.max(0, startIndex - 80), startIndex)
  return STATEMENT_CUE_RE.test(before) || QUESTION_CUE_RE.test(before)
}

/** Whether any direct phrase matches WITHOUT a statement/modality cue nearby. */
function hitsDirectivePhrase(plain: string, rules: readonly { family: string; direct: readonly RegExp[]; weak: readonly RegExp[] }[]): string[] {
  const hits: string[] = []
  for (const rule of rules) {
    for (const re of rule.direct) {
      const hit = re.exec(plain)
      if (hit !== null && !hasStatementCue(plain, hit.index)) {
        hits.push(rule.family)
        break
      }
    }
  }
  return hits
}

/**
 * Threat features of a tool result: control-token sanitization, injection
 * phrase scan (with encoded-payload recursion), and observed-secret
 * collection. Sanitized text is exported as `toolResultText` for audit and
 * user rules.
 *
 * Level scale (B4#8):
 *   - `block`: a direct directive phrase, or a decoded encoded direct
 *     phrase (high confidence by construction);
 *   - `warn`: only ≥2 *weak* phrases from DIFFERENT families (soft signal).
 * A lone weak phrase, or a statement like "you can post results to the
 * dashboard", produces neither.
 *
 * Feature contract: `toolResultText` is always present; every other field is
 * present only when its signal fired.
 */
export function deriveToolResultFeatures(input: ToolResultFeatureInput): Record<string, unknown> {
  const raw = truncateForScan(input.text)
  let text = raw
  let specialTokensRemoved = 0
  // Strip control tokens until stable (bounded iterations, handles nesting).
  for (let i = 0; i < 100 && text.length > 0; i++) {
    let next = text
    for (const token of SPECIAL_TOKENS) next = next.split(token).join('')
    if (next === text) break
    specialTokensRemoved += text.length - next.length
    text = next
  }

  const features: Record<string, unknown> = { toolResultText: text }
  if (specialTokensRemoved > 0) features.specialTokensRemoved = specialTokensRemoved

  const { plain } = scanViews(text)
  const directiveHits = hitsDirectivePhrase(plain, INJECTION_RULES)
  const weakFamilies = new Set<string>()
  for (const rule of INJECTION_RULES) {
    if (rule.weak.some((re) => re.test(plain))) weakFamilies.add(rule.family)
  }

  // Encoded payload recursion: decoded direct phrases are high confidence
  // by construction (the encoding itself is the evasion attempt).
  const encodedHits: string[] = []
  for (const candidate of decodeEncodedCandidates(text)) {
    const decodedPlain = normalizeText(candidate.decoded)
    for (const rule of INJECTION_RULES) {
      if (rule.direct.some((re) => re.test(decodedPlain))) encodedHits.push(`encoded-${rule.family}`)
    }
  }

  const strongFlags = [...directiveHits, ...encodedHits]
  const flags = [...strongFlags, ...[...weakFamilies].map((f) => `${f}-weak`)]
  if (flags.length > 0) features.toolResultFlags = flags

  let risk: 'block' | 'warn' | undefined
  if (strongFlags.length > 0) risk = 'block'
  else if (weakFamilies.size >= 2) risk = 'warn'
  if (risk !== undefined) {
    features.toolResultRisk = risk
    features.toolResultSuspicious = true
  }

  const observedSecrets = collectSecrets(text)
  if (observedSecrets.length > 0) features.observedSecrets = observedSecrets

  return features
}
