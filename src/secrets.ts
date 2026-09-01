/**
 * Observed-secret detection: known credential prefixes, key=value pairs, and
 * high-entropy tokens, plus encoding variants so a base64/hex-re-encoded
 * secret is still recognized inside an outbound command.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/secrets
 */

/** Known credential prefixes (case-insensitive comparison at detection). */
export const KEY_PREFIXES: readonly string[] = [
  'sk-', 'sk_live_', 'sk-proj-', 'sk-ant-', 'ghp_', 'gho_', 'github_pat_', 'glpat-',
  'xoxb-', 'xoxp-', 'AKIA', 'ASIA', 'AIza', 'ya29.', 'eyJ', 'glrt-', 'AKLT',
]

/** Placeholder / sample values that must never count as secrets. */
const PLACEHOLDER_RE = /^(xxx+|\*{3,}|<[^>]*>|\$\{[^}]*\}|changeme[a-z0-9_-]*|change[_-]?me|placeholder[a-z0-9_-]*|your[_-][a-z0-9_-]+|example[a-z0-9_-]*|dummy[a-z0-9_-]*|sample[a-z0-9_-]*|test[a-z0-9_-]*|fake[a-z0-9_-]*|redacted|none|null|nil|na|n\/a|\?+)$/i

/** Base64-ish token shape (16+ alphabet chars with optional padding). */
const BASE64ISH_RE = /[a-z0-9+/]{16,}={0,2}/i

/** Continuous high-entropy token (24+ chars). Standalone candidate.
 * Character class is deliberately path-separator / dot free, so long paths
 * (`…/build-output-2026.tar.gz`) and dotted identifiers never enter the
 * candidate pool. */
const STANDALONE_RE = /[a-z0-9+/=_-]{24,}/gi

/** Key=value pair where the value is long enough to be a secret. */
const KEY_EQ_VALUE_RE = /[a-z0-9_-]+="?[^"\s]{12,}"?/gi

/** Prefix-led token candidate (`sk-…`, `ghp_…`, …). */
const PREFIX_TOKEN_RE = /(?:sk-|sk_live_|sk-proj-|sk-ant-|ghp_|gho_|github_pat_|glpat-|xoxb-|xoxp-|AKIA|ASIA|AIza|ya29\.|eyJ|glrt-|AKLT)[a-z0-9+/=_\-.]{8,}/gi

/** Minimum distinct characters a base64-ish / standalone token must contain. */
const MIN_DISTINCT_CHARS = 8
/** Shortest value that can qualify as a secret on character-diversity alone. */
const MIN_SECRET_LENGTH = 16
/** How many distinct character kinds a credential-like value must mix. */
const MIN_CHAR_KINDS = 2

/**
 * How many distinct character kinds (lower / upper / digit / other) a value
 * mixes. Real credentials almost never sit in a single kind.
 */
function charKinds(value: string): number {
  let kinds = 0
  for (const kind of [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/]) {
    if (kind.test(value)) kinds += 1
  }
  return kinds
}

/**
 * Heuristic: does `value` look like a real secret? Minimum length 8, known
 * prefix, or base64-ish/entropy shape. Path-shaped values (contain `/`),
 * dotted identifiers and placeholder/sample values never count. A directory
 * listing is not a leak (B4#9).
 */
export function looksSensitiveValue(value: string): boolean {
  if (value.length < 8) return false
  if (PLACEHOLDER_RE.test(value)) return false
  // Paths / URLs (any `/`) are never a single secret value.
  if (value.includes('/') || value.includes('\\')) return false
  if (KEY_PREFIXES.some((prefix) => value.startsWith(prefix))) return true
  // Dotted or dashed identifier shapes (build-output-2026, request.id) are not
  // secrets; if they carry a known prefix they were already caught above.
  if (/^[a-z0-9]+(?:[._-][a-z0-9]+)+$/i.test(value)) return false
  const distinct = new Set(value.toLowerCase()).size
  if (distinct < MIN_DISTINCT_CHARS) return false
  if (BASE64ISH_RE.test(value)) return charKinds(value) >= MIN_CHAR_KINDS
  return charKinds(value) >= MIN_CHAR_KINDS && value.length >= MIN_SECRET_LENGTH
}

/** Collect the distinct sensitive values found in a text. */
export function collectSecrets(text: string): string[] {
  const secrets = new Set<string>()
  const add = (value: string): void => {
    if (looksSensitiveValue(value)) secrets.add(value)
  }
  for (const match of text.matchAll(PREFIX_TOKEN_RE)) {
    const token = match[0]
    if (token !== undefined) add(token)
  }
  for (const match of text.matchAll(STANDALONE_RE)) {
    const token = match[0]
    if (token !== undefined) add(token)
  }
  for (const match of text.matchAll(KEY_EQ_VALUE_RE)) {
    const token = match[0]
    if (token === undefined) continue
    const equals = token.indexOf('=')
    if (equals > 0) add(token.slice(equals + 1).replace(/^"|"$/g, ''))
  }
  return [...secrets]
}

/** A secret plus its common encoded forms, for matching inside commands. */
export function secretVariants(secret: string): string[] {
  const variants = new Set<string>([secret, secret.trim()])
  try {
    variants.add(Buffer.from(secret, 'utf8').toString('base64'))
    variants.add(Buffer.from(secret, 'utf8').toString('hex'))
  } catch {
    // never throws for strings; defensive
  }
  return [...variants]
}
