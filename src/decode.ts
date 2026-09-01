/**
 * Bounded encoded-payload decoding.
 *
 * Recursively (max depth 2) pulls base64 / hex tokens out of a text
 * and decodes them, so `echo <b64> | base64 -d` style payloads, and payloads
 * that are themselves base64 of base64, surface for downstream pattern
 * matching. Hard bounds: depth 2, total decoded output `MAX_DECODED_CHARS`,
 * and a printable-ratio filter (>= 0.7) so random base64-ish junk is ignored.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/decode
 */

import { MAX_DECODED_CHARS } from './normalize.ts'

/** One decoded payload candidate, in detection order. */
export interface DecodedCandidate {
  kind: 'base64' | 'hex'
  /** The source token (bounded by the scan text length). */
  encoded: string
  /** Decoded text; may be truncated by the budget. */
  decoded: string
  /** Nesting depth, 1 = direct token in the input. */
  depth: number
}

const B64_RE = /\b[a-z0-9+/]{16,}={0,2}(?!\w)/gi
const B64_URL_SAFE_RE = /\b[a-z0-9_-]{16,}={0,2}(?!\w)/gi
const HEX_RE = /\b(?:[a-f0-9]{2}){16,}(?!\w)/gi
/**
 * Short base64 tokens only count when they carry padding (`=`/`==`), which is
 * a strong real-base64 signal: `cm0gLXJmIC8=` (base64 of `rm -rf /`) is only
 * 12 chars and is otherwise invisible at the 16-char minimum. `=` never
 * appears in random word tokens, so this cannot pull in ordinary text.
 * Note the `(?!\w)` tail instead of `\b`: `\b` after a trailing `=` never
 * matches (both sides non-word), so padded base64 would otherwise be missed.
 */
const B64_SHORT_PADDED_RE = /\b[a-z0-9+/_-]{8,}={1,2}(?!\w)/gi

/** Decoded output must be at least this share of printable ASCII to count. */
const MIN_PRINTABLE_RATIO = 0.7
/** Maximum nesting depth. */
const MAX_DEPTH = 2
/** Minimum token length to attempt decoding (short tokens must carry padding). */
const MIN_TOKEN_LEN = 8

function printableRatio(text: string): number {
  let printable = 0
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i)
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code < 127)) printable += 1
  }
  return printable / text.length
}

function tryBase64(token: string): string | undefined {
  const standard = token.replace(/-/g, '+').replace(/_/g, '/')
  try {
    // UTF-8 first, the normal payload encoding, which also keeps random
    // base64-ish junk from accidentally "decoding clean" as UTF-16LE pairs.
    const utf8 = Buffer.from(standard, 'base64').toString('utf8')
    if (utf8.length > 0 && printableRatio(utf8) >= MIN_PRINTABLE_RATIO) return utf8
    // UTF-16LE fallback for PowerShell `-enc` payloads, whose NUL-heavy bytes
    // defeat the printable-ratio filter (B3.3): `cgBtACAALQByAGYAIAAvAA==`
    // decodes as UTF-16LE to `rm -rf /`. Only adopted when UTF-8 failed, so
    // ordinary base64 payloads are unaffected.
    const utf16 = Buffer.from(standard, 'base64').toString('utf16le')
    if (utf16.length > 0 && printableRatio(utf16) >= MIN_PRINTABLE_RATIO) return utf16
  } catch {
    // fallthrough to undefined
  }
  return undefined
}

function tryHex(token: string): string | undefined {
  try {
    const decoded = Buffer.from(token, 'hex').toString('utf8')
    if (decoded.length === 0 || printableRatio(decoded) < MIN_PRINTABLE_RATIO) return undefined
    return decoded
  } catch {
    return undefined
  }
}

function decodeToken(token: string): { kind: 'base64' | 'hex'; decoded: string } | undefined {
  if (token.length < MIN_TOKEN_LEN) return undefined
  const base64 = tryBase64(token)
  if (base64 !== undefined) return { kind: 'base64', decoded: base64 }
  const hex = tryHex(token)
  if (hex !== undefined) return { kind: 'hex', decoded: hex }
  return undefined
}

/**
 * Every candidate token of `input` at one nesting level (deduped by caller).
 * Operates on RAW text: base64 is case-sensitive, so lowercasing here would
 * corrupt mixed-case payloads before decoding.
 */
function scan(input: string): string[] {
  const tokens: string[] = []
  for (const re of [B64_RE, B64_URL_SAFE_RE, B64_SHORT_PADDED_RE, HEX_RE]) {
    for (const match of input.matchAll(re)) {
      const token = match[0]
      if (token !== undefined) tokens.push(token)
    }
  }
  return tokens
}

/**
 * Decode every nested payload candidate in `text`, bounded by depth and total
 * output. Candidates are returned outermost-first (depth 1 first).
 */
export function decodeEncodedCandidates(text: string, maxOutput = MAX_DECODED_CHARS): DecodedCandidate[] {
  const found: DecodedCandidate[] = []
  const seen = new Set<string>()
  let remaining = maxOutput

  const consider = (token: string, depth: number): void => {
    if (depth > MAX_DEPTH || seen.has(token) || remaining <= 0) return
    seen.add(token)
    const decodedToken = decodeToken(token)
    if (decodedToken === undefined) return

    const chunk = decodedToken.decoded.length > remaining
      ? decodedToken.decoded.slice(0, remaining)
      : decodedToken.decoded
    remaining -= chunk.length
    found.push({ kind: decodedToken.kind, encoded: token, decoded: chunk, depth })

    for (const inner of scan(chunk)) consider(inner, depth + 1)
  }

  for (const token of scan(text)) consider(token, 1)
  return found
}
