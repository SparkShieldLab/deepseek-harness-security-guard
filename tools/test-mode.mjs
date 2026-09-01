// node:test suite for engine monitor mode (runs against lib/ after `npm run build`).
// Usage: npm run build && node --test tools/
import test from 'node:test'
import assert from 'node:assert/strict'
import { GuardEngine } from '../lib/engine.js'

/** Build one block/warn/allow/ask policy; `mode` added only when given. */
function policy(mode, action = 'block') {
  return {
    id: 'p',
    hooks: ['before_tool_call'],
    priority: 100,
    action,
    message: 'p',
    ...(mode === undefined ? {} : { mode }),
    rules: [{ field: 'toolName', operator: 'eq', value: 'bash' }],
  }
}

test('mode: default protect blocks', () => {
  const e = new GuardEngine([policy(undefined)])
  const d = e.decide({ eventType: 'before_tool_call', data: { toolName: 'bash' }, context: {} })
  assert.equal(d.action, 'block')
  assert.equal(d.monitorDowngraded, undefined)
})

test('mode: monitor downgrades block to warn', () => {
  const e = new GuardEngine([policy('monitor')])
  const d = e.decide({ eventType: 'before_tool_call', data: { toolName: 'bash' }, context: {} })
  assert.equal(d.action, 'warn')
  assert.equal(d.monitorDowngraded, true)
})

test('mode: monitor downgrades ask to warn', () => {
  const e = new GuardEngine([policy('monitor', 'ask')])
  const d = e.decide({ eventType: 'before_tool_call', data: { toolName: 'bash' }, context: {} })
  assert.equal(d.action, 'warn')
})

test('mode: engine default mode applies to policies without mode', () => {
  const e = new GuardEngine([policy(undefined)], true, 'monitor')
  const d = e.decide({ eventType: 'before_tool_call', data: { toolName: 'bash' }, context: {} })
  assert.equal(d.action, 'warn')
  assert.equal(d.monitorDowngraded, true)
})

test('mode: per-policy mode overrides engine default', () => {
  const e = new GuardEngine([policy('protect')], true, 'monitor')
  const d = e.decide({ eventType: 'before_tool_call', data: { toolName: 'bash' }, context: {} })
  assert.equal(d.action, 'block')
})

test('mode: allow stays allow under monitor', () => {
  const e = new GuardEngine([policy('monitor', 'allow')])
  const d = e.decide({ eventType: 'before_tool_call', data: { toolName: 'bash' }, context: {} })
  assert.equal(d.action, 'allow')
})

test('mode: warn stays warn under monitor without downgrade flag', () => {
  const e = new GuardEngine([policy('monitor', 'warn')])
  const d = e.decide({ eventType: 'before_tool_call', data: { toolName: 'bash' }, context: {} })
  assert.equal(d.action, 'warn')
  assert.equal(d.monitorDowngraded, undefined)
})

test('mode: disabled engine short-circuits every decision to allow', () => {
  const e = new GuardEngine([policy(undefined)], true, 'protect')
  assert.equal(e.enabled, true, 'enabled by default')
  e.setEnabled(false)
  assert.equal(e.enabled, false)
  const d = e.decide({ eventType: 'before_tool_call', data: { toolName: 'bash' }, context: {} })
  assert.equal(d.action, 'allow')
  assert.equal(d.policyId, undefined, 'no policy matched while disabled')
})

test('mode: re-enabling restores enforcement', () => {
  const e = new GuardEngine([policy(undefined)])
  e.setEnabled(false)
  assert.equal(e.decide({ eventType: 'before_tool_call', data: { toolName: 'bash' }, context: {} }).action, 'allow')
  e.setEnabled(true)
  assert.equal(e.decide({ eventType: 'before_tool_call', data: { toolName: 'bash' }, context: {} }).action, 'block')
})
