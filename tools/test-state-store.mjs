// node:test suite for the guard state store (runs against lib/ after `npm run build`).
// Usage: npm run build && node --test tools/
import test from 'node:test'
import assert from 'node:assert/strict'
import { GuardStateStore, REPEAT_CALL_BUDGET } from '../lib/state-store.js'

test('state: loop counters are per session/turn/key', () => {
  const s = new GuardStateStore()
  assert.equal(s.countRepeat('s1', 1, 'k'), 1)
  assert.equal(s.countRepeat('s1', 1, 'k'), 2)
  assert.equal(s.countRepeat('s1', 2, 'k'), 1)
  assert.equal(s.countRepeat('s2', 1, 'k'), 1)
})

test('state: loop guard fires after the allow count', () => {
  const s = new GuardStateStore()
  for (let i = 0; i < REPEAT_CALL_BUDGET; i++) s.countRepeat('s1', 1, 'k')
  assert.equal(s.countRepeat('s1', 1, 'k'), REPEAT_CALL_BUDGET + 1)
})

test('state: secrets, risk flags, artifacts, signals persist per session', () => {
  const s = new GuardStateStore()
  s.noteSecrets('s1', ['sk-abc123'])
  assert.deepEqual(s.peekSecrets('s1'), ['sk-abc123'])
  s.noteRiskFlags('s1', ['encoded-persona-hijack'])
  assert.deepEqual(s.peekRiskFlags('s1'), ['encoded-persona-hijack'])
  s.noteArtifact('s1', 1, { path: '/ws/x.sh', hash: 'a1', risk: true, outbound: true })
  assert.equal(s.peekArtifacts('s1', 1).length, 1)
  s.noteSignals('s1', 1, { credential: true })
  assert.deepEqual(s.peekSignals('s1', 1), { credential: true, encoding: false, egress: false, outboundCalls: 0, riskyArtifact: false })
  s.noteSignals('s1', 1, { outboundCalls: 1 })
  assert.equal(s.peekSignals('s1', 1)?.outboundCalls, 1)
})

test('state: clearSession drops everything for a session', () => {
  const s = new GuardStateStore()
  s.noteSecrets('s1', ['sk-abc123'])
  s.noteRiskFlags('s1', ['f'])
  s.countRepeat('s1', 1, 'k')
  s.clearSession('s1')
  assert.deepEqual(s.peekSecrets('s1'), [])
  assert.deepEqual(s.peekRiskFlags('s1'), [])
  assert.equal(s.peekSignals('s1', 1), undefined)
  assert.deepEqual(s.peekArtifacts('s1', 1), [])
})

test('state: TTL expiry cleans up (short TTL)', async () => {
  const s = new GuardStateStore(20)
  s.noteSecrets('s1', ['sk-abc123'])
  s.countRepeat('s1', 1, 'k')
  await new Promise((resolve) => setTimeout(resolve, 40))
  assert.deepEqual(s.peekSecrets('s1'), [])
  assert.equal(s.peekSignals('s1', 1), undefined)
})
