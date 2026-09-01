// node:test suite for the UI policy-config feature (runs against lib/ after `npm run build`).
// Usage: npm run build && node --test tools/
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { GuardEngine } from '../lib/engine.js'
import { UiPolicyTable } from '../lib/config.js'
import { PolicyFileStore, policyStorePaths } from '../lib/policy-store.js'

test('engine: after setPolicies, decisions change immediately and version increments', () => {
  const engine = new GuardEngine([
    { id: 'p1', hooks: ['before_tool_call'], priority: 100, action: 'block',
      message: 'm', rules: [{ field: 'toolName', operator: 'eq', value: 'bash' }] },
  ])
  const ev = { eventType: 'before_tool_call', data: { toolName: 'bash' }, context: {} }
  assert.equal(engine.decide(ev).action, 'block')
  assert.equal(engine.version, 0)

  engine.setPolicies([
    { id: 'p2', hooks: ['before_tool_call'], priority: 100, action: 'ask',
      message: 'm2', rules: [{ field: 'toolName', operator: 'eq', value: 'bash' }] },
  ])
  assert.equal(engine.decide(ev).action, 'ask')
  assert.equal(engine.version, 1)
})

test('UiPolicyTable: a valid table passes (defaults filled in), an invalid table yields issues', () => {
  const ok = UiPolicyTable['~standard'].validate({
    v: 1,
    policies: [{
      id: 'a',
      hooks: ['before_tool_call'],
      rules: [{ id: 'r', field: 'toolName', operator: 'in', value: ['bash'] }],
      action: 'block',
    }],
  })
  assert.equal(ok.issues, undefined)
  const table = ok.value
  assert.equal(table.v, 1)
  assert.equal(table.reset, false) // defaults to false
  const p = table.policies[0]
  assert.equal(p.enabled, true)  // defaults filled in
  assert.equal(p.priority, 100)

  const bad = UiPolicyTable['~standard'].validate({
    v: 1,
    policies: [{ id: 'a', rules: [{ field: 'f', operator: 'nope', value: 1 }], action: 'block' }],
  })
  assert.ok(bad.issues)

  const badV = UiPolicyTable['~standard'].validate({ v: 2, policies: [] })
  assert.ok(badV.issues)
})

// ---------------------------------------------------------------------------
// PolicyFileStore
// ---------------------------------------------------------------------------

/** cordis.yml baseline: no policies (allow everything) — observable flips. */
const BASE = []
const GOOD = [{
  id: 'block-bash', hooks: ['before_tool_call'], priority: 200, action: 'block',
  message: 'no bash', rules: [{ id: 'r1', field: 'toolName', operator: 'eq', value: 'bash' }],
}]
const BAD_OPERATOR = [{
  id: 'x', hooks: ['*'], priority: 100, action: 'block', message: 'm',
  rules: [{ id: 'r', field: 'toolName', operator: 'nope', value: 'bash' }],
}]

const BASH_EVENT = { eventType: 'before_tool_call', data: { toolName: 'bash' }, context: {} }

function makeStore(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-store-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const engine = new GuardEngine(BASE)
  const logger = { info() {}, warn() {}, debug() {} }
  const store = new PolicyFileStore({ dir, basePolicies: BASE, engine, logger, watchIntervalMs: 50 })
  return { store, engine, logger }
}

test('store: start without a file -> cordis baseline, effective.json written to disk', (t) => {
  const { store, engine } = makeStore(t)
  store.start()
  t.after(() => store.stop())
  assert.equal(store.state().source, 'cordis.yml')
  assert.equal(engine.version, 0)
  const eff = JSON.parse(fs.readFileSync(store.effectivePath, 'utf8'))
  assert.equal(eff.source, 'cordis.yml')
  assert.deepEqual(eff.policies, [])
  assert.equal(eff.error, undefined)
})

test('store: after sync with a valid file, the hot table swap takes effect and is mirrored', (t) => {
  const { store, engine } = makeStore(t)
  store.start()
  t.after(() => store.stop())
  fs.writeFileSync(store.uiPoliciesPath, JSON.stringify({ v: 1, policies: GOOD }))
  store.sync()
  assert.equal(store.state().source, 'ui-policies.json')
  assert.equal(engine.decide(BASH_EVENT).action, 'block')
  assert.ok(engine.version > 0)
  const eff = JSON.parse(fs.readFileSync(store.effectivePath, 'utf8'))
  assert.equal(eff.source, 'ui-policies.json')
  assert.equal(eff.policies[0].id, 'block-bash')
  assert.equal(eff.error, undefined)
})

test('store: bad JSON / invalid table / duplicate content -> keep the last good state and version does not increment', (t) => {
  const { store, engine } = makeStore(t)
  store.start()
  t.after(() => store.stop())
  fs.writeFileSync(store.uiPoliciesPath, JSON.stringify({ v: 1, policies: GOOD }))
  store.sync()
  assert.equal(engine.decide(BASH_EVENT).action, 'block')

  fs.writeFileSync(store.uiPoliciesPath, '{ not json')
  store.sync()
  assert.ok(store.state().error)
  assert.equal(engine.decide(BASH_EVENT).action, 'block') // keeps the good state
  let eff = JSON.parse(fs.readFileSync(store.effectivePath, 'utf8'))
  assert.ok(eff.error)
  assert.equal(eff.policies[0].id, 'block-bash')

  const vBefore = engine.version
  const bad = JSON.stringify({ v: 1, policies: BAD_OPERATOR })
  fs.writeFileSync(store.uiPoliciesPath, bad)
  store.sync()
  assert.ok(store.state().error)
  assert.equal(engine.version, vBefore) // invalid -> no new generation

  fs.writeFileSync(store.uiPoliciesPath, bad) // content unchanged
  store.sync()
  assert.equal(engine.version, vBefore) // deduped
})

test('store: reset marker -> restore baseline and delete the file', (t) => {
  const { store, engine } = makeStore(t)
  store.start()
  t.after(() => store.stop())
  fs.writeFileSync(store.uiPoliciesPath, JSON.stringify({ v: 1, policies: GOOD }))
  store.sync()
  assert.equal(engine.decide(BASH_EVENT).action, 'block')

  fs.writeFileSync(store.uiPoliciesPath, JSON.stringify({ v: 1, reset: true }))
  store.sync()
  assert.throws(() => fs.readFileSync(store.uiPoliciesPath, 'utf8'))
  assert.equal(store.state().source, 'cordis.yml')
  assert.equal(store.state().error, undefined)
  assert.equal(engine.decide(BASH_EVENT).action, 'allow') // back to baseline
  const eff = JSON.parse(fs.readFileSync(store.effectivePath, 'utf8'))
  assert.equal(eff.source, 'cordis.yml')
  assert.equal(eff.error, undefined)
  assert.deepEqual(eff.policies, [])
})

test('store: a valid file already exists at start -> loaded on startup', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-store-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const engine = new GuardEngine(BASE)
  const logger = { info() {}, warn() {}, debug() {} }
  fs.writeFileSync(path.join(dir, 'ui-policies.json'), JSON.stringify({ v: 1, policies: GOOD }))
  const store = new PolicyFileStore({ dir, basePolicies: BASE, engine, logger, watchIntervalMs: 50 })
  store.start()
  t.after(() => store.stop())
  assert.equal(store.state().source, 'ui-policies.json')
  assert.equal(engine.decide(BASH_EVENT).action, 'block')
})

test('policyStorePaths: agent-security-guard directory under DSH_HOME, absolute paths', () => {
  const p = policyStorePaths()
  assert.equal(path.isAbsolute(p.uiPoliciesPath), true)
  assert.equal(p.uiPoliciesPath.endsWith(path.join('agent-security-guard', 'ui-policies.json')), true)
  assert.equal(p.effectivePath.endsWith(path.join('agent-security-guard', 'effective.json')), true)
  assert.equal(path.dirname(p.uiPoliciesPath), p.dir)
})
