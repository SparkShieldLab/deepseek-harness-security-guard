/**
 * Command/content threat features merged from the operator_rules.yml baseline
 * (deduplicated merge into the execution layer). Families absent from the
 * legacy feature set only; destructive commands, reverse shells and
 * protected-path reads are already covered by `features.ts` (highRisk /
 * protectedPathHit) and deliberately NOT re-scanned here (dedupe).
 *
 * The ROWS live in the platform-adaptive threat catalogue
 * (`threat-catalog.ts`): the active set is the host's (shared + platform),
 * armed at plugin load. Feature contract: fields appear ONLY when a signal
 * fired. Tiered families (`privEsc`, `systemPathWrite`, `sandboxEscape`)
 * resolve to `'block'` or `'warn'`; boolean families are warn-tier audit
 * signals.
 *
 * Command patterns run on `normalizeText` output (lowercased, invisible chars
 * stripped): rows are lowercase, no /i flag. The memory-target gate runs on
 * the RAW path argument (case preserved) and is therefore case-insensitive.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/command-threats
 */

import { COMMAND_TEXT_LIMIT, normalizeText } from './normalize.ts'
import { activeThreatCatalog } from './threat-catalog.ts'

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

/**
 * Derive command/content threat features for one tool call. Fields appear
 * only on a hit; `{}` when nothing fired. Tiered families carry `'block'` or
 * `'warn'`, boolean families are warn-tier audit signals.
 */
export function deriveCommandThreatFeatures(
  args: Record<string, unknown>,
): Record<string, unknown> {
  const c = activeThreatCatalog()
  const rawCommand = firstString(args, ['command', 'cmd', 'shell', 'code']) ?? ''
  const command = normalizeText(rawCommand.slice(0, COMMAND_TEXT_LIMIT))
  const features: Record<string, unknown> = {}
  if (command.length > 0) {
    const hit = (rows: readonly RegExp[]): boolean => rows.some((re) => re.test(command))
    const t = (blockRows: readonly RegExp[], warnRows: readonly RegExp[]): 'block' | 'warn' | undefined =>
      tier(command, blockRows, warnRows)
    const privEsc = t(c.privEscBlock, c.privEscWarn)
    if (privEsc !== undefined) features.privEsc = privEsc
    const systemPathWrite = t(c.systemPathWriteBlock, c.systemPathWriteWarn)
    if (systemPathWrite !== undefined) features.systemPathWrite = systemPathWrite
    if (hit(c.configTamper)) features.configTamper = true
    const sandboxEscape = t(c.sandboxEscapeBlock, c.sandboxEscapeWarn)
    if (sandboxEscape !== undefined) features.sandboxEscape = sandboxEscape
    if (hit(c.netRecon)) features.netRecon = true
    if (hit(c.pathTraversal)) features.pathTraversal = true
    if (hit(c.untrustedSource)) features.untrustedSource = true
    if (hit(c.insecureRegistry)) features.insecureRegistry = true
    if (hit(c.secretLogging)) features.secretLogging = true
  }
  // Write-like calls: directive content aimed at a memory-like target is the
  // 6xx long-term-memory-poisoning face. The path gate keeps ordinary notes
  // clean; a directive with no path at all still fires (unambiguous abuse).
  const rawContent = firstString(args, CONTENT_KEYS) ?? ''
  const content = normalizeText(rawContent.slice(0, COMMAND_TEXT_LIMIT))
  if (content.length > 0) {
    const path = firstString(args, PATH_KEYS)
    const directive = c.memoryPoisonContent.some((re) => re.test(content))
    if (directive && (path === undefined || c.memoryTarget.test(path))) {
      features.memoryPoisonWrite = true
    }
  }
  return features
}
