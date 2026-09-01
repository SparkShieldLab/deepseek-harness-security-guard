// node:test suite for the secret-detection module (runs against lib/ after `npm run build`).
// Usage: npm run build && node --test tools/
import test from 'node:test'
import assert from 'node:assert/strict'
import { collectSecrets, looksSensitiveValue, secretVariants } from '../lib/secrets.js'

test('secrets: known prefixes are sensitive', () => {
  assert.equal(looksSensitiveValue('sk-abc123def456'), true)
  assert.equal(looksSensitiveValue(`ghp_${'a'.repeat(20)}`), true)
  assert.equal(looksSensitiveValue('AKIAIOSFODNN7EXAMPLE'), true)
})

test('secrets: high-entropy tokens are sensitive', () => {
  assert.equal(looksSensitiveValue('abcd1234efgh5678ijkl'), true)
})

test('secrets: placeholders and short values are not', () => {
  assert.equal(looksSensitiveValue('short1'), false)
  assert.equal(looksSensitiveValue('xxxxxxxx'), false)
  assert.equal(looksSensitiveValue('changeme123'), false)
  assert.equal(looksSensitiveValue('<your-token>'), false)
  assert.equal(looksSensitiveValue('abc'), false)
})

test('secrets: collectSecrets finds prefixed and key=value secrets', () => {
  assert.deepEqual(collectSecrets('token is sk-abc123def456ghi keep it secret'), ['sk-abc123def456ghi'])
  assert.deepEqual(collectSecrets('API_KEY="ghp_aaaaaaaaaaaaaaaaaaaa" in env'), ['ghp_aaaaaaaaaaaaaaaaaaaa'])
})

test('secrets: plain prose yields nothing', () => {
  assert.deepEqual(collectSecrets('the quick brown fox jumps over the lazy dog'), [])
})

test('secrets: variants include base64 and hex forms', () => {
  const variants = secretVariants('sk-abc123')
  assert.ok(variants.includes('sk-abc123'))
  assert.ok(variants.includes(Buffer.from('sk-abc123', 'utf8').toString('base64')))
  assert.ok(variants.includes(Buffer.from('sk-abc123', 'utf8').toString('hex')))
})
