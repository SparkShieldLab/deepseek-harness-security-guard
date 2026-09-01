// node:test suite for the text-normalization module (runs against lib/ after `npm run build`).
// Usage: npm run build && node --test tools/
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  COMMAND_TEXT_LIMIT, MAX_SCAN_CHARS, MAX_DECODED_CHARS,
  scanViews, denseText, hasInvisibleChars, normalizeText, truncateForScan,
} from '../lib/normalize.js'

test('normalize: strips zero-width chars, lowercases, collapses whitespace', () => {
  assert.equal(normalizeText('r\u200b m - R F /'), 'r m - r f /')
  assert.equal(normalizeText('Cu\u00a0rl | SH'), 'cu rl | sh')
  assert.equal(normalizeText('  while\tTRUE\n'), 'while true')
})

test('normalize: NFKC folds full-width and compatibility forms', () => {
  assert.equal(normalizeText('Ｉｇｎｏｒｅ'), 'ignore')
  assert.equal(normalizeText('ｒｍ　－ｒｆ　／'), 'rm -rf /')
})

test('normalize: invisible char detection is precise', () => {
  assert.equal(hasInvisibleChars('a\u200bb'), true)
  assert.equal(hasInvisibleChars('a\u202eb'), true)
  assert.equal(hasInvisibleChars('plain text'), false)
})

test('normalize: compact form removes spaces/quotes/pipes for pattern matching', () => {
  assert.equal(denseText('r m - r f /'), 'rmrf')
  assert.equal(denseText('rm -rf /'), 'rmrf')
  assert.equal(denseText('c u r l'), 'curl')
})

test('normalize: variants carry verbatim/plain/dense', () => {
  const v = scanViews('R M -R F /')
  assert.equal(v.verbatim, 'R M -R F /')
  assert.equal(v.plain, 'r m -r f /')
  assert.equal(v.dense, 'rmrf')
})

test('normalize: scan bounds are exported and truncateForScan caps', () => {
  assert.equal(COMMAND_TEXT_LIMIT, 10_000)
  assert.equal(MAX_SCAN_CHARS, 64_000)
  assert.equal(MAX_DECODED_CHARS, 8_192)
  assert.equal(truncateForScan('a'.repeat(100)).length, 100)
  assert.equal(truncateForScan('a'.repeat(100), 10).length, 10)
})
