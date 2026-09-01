/**
 * Text conditioning + scan bounds.
 *
 * Downstream matchers never see ad-hoc strings: every scan is bounded to a
 * constant worst-case size, and every match runs over conditioned text that
 * neutralizes case / spacing / zero-width / unicode-evasion tricks. Each text
 * is viewed three ways: `verbatim` (as received), `plain` (invisible chars
 * stripped, NFKC, whitespace collapsed, lowercase, trimmed), and `dense`
 * (`plain` minus every non-alphanumeric char, so letter-spaced payloads like
 * `r m - r f /` still match).
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/normalize
 */

/** Longest command string a single tool call contributes to scanning. */
export const COMMAND_TEXT_LIMIT = 10_000
/** Upper bound on one prompt/tool-result text scan. */
export const MAX_SCAN_CHARS = 64_000
/** Upper bound on total decoded payload text per event. */
export const MAX_DECODED_CHARS = 8_192

/** Zero-width / bidi / soft-hyphen / word-joiner code points (global, for replace). */
const INVISIBLE_RE = /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad\u1806]/g
/** Special whitespace that still renders as space (global, for replace). */
const SPECIAL_SPACE_RE = /[\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/g
/** Non-global copies for stateless .test(). */
const INVISIBLE_TEST_RE = /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad\u1806]/
const SPECIAL_SPACE_TEST_RE = /[\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/

/** True when text contains zero-width / bidi / special-space code points. */
export function hasInvisibleChars(text: string): boolean {
  return INVISIBLE_TEST_RE.test(text) || SPECIAL_SPACE_TEST_RE.test(text)
}

/** Canonical lowercase form used by every matcher. */
export function normalizeText(text: string): string {
  return text
    .replace(INVISIBLE_RE, '')
    .replace(SPECIAL_SPACE_RE, ' ')
    .normalize('NFKC')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase()
}

/** `plain` text reduced to alphanumerics only (defeats letter-spacing tricks). */
export function denseText(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]/g, '')
}

/** The three matching views of one text. */
export interface ScanViews {
  /** As received, untouched. */
  verbatim: string
  /** Invisible-char-stripped, NFKC, whitespace-collapsed, lowercase, trimmed. */
  plain: string
  /** `plain` with every non-alphanumeric char removed. */
  dense: string
}

/** Build the matching views of a text. */
export function scanViews(text: string): ScanViews {
  const plain = normalizeText(text)
  return { verbatim: text, plain, dense: denseText(plain) }
}

/** Cap a text at `maxChars` (default {@link MAX_SCAN_CHARS}). */
export function truncateForScan(text: string, maxChars = MAX_SCAN_CHARS): string {
  return text.length > maxChars ? text.slice(0, maxChars) : text
}
