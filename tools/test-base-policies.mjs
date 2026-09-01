// node:test suite for the baseline policy table (runs against lib/ after `npm run build`).
// Usage: npm run build && node --test tools/
import test from 'node:test'
import assert from 'node:assert/strict'
import { BASELINE_PRIORITY, baselinePolicies } from '../lib/base-policies.js'
import { GuardEngine } from '../lib/engine.js'

test('baseline: 27 policies, priority 50, ids unique', () => {
  const policies = baselinePolicies()
  assert.equal(policies.length, 27)
  assert.ok(policies.every((p) => p.priority === BASELINE_PRIORITY))
  assert.equal(new Set(policies.map((p) => p.id)).size, policies.length)
})

test('baseline: high-risk command is blocked', () => {
  const engine = new GuardEngine(baselinePolicies())
  const decision = engine.decide({
    eventType: 'before_tool_call',
    data: { toolName: 'bash', command: 'rm -rf /', highRisk: true },
    context: {},
  })
  assert.equal(decision.action, 'block')
  assert.equal(decision.policyId, 'base-block-high-risk-command')
})

test('baseline: protected path and outside delete are blocked', () => {
  const engine = new GuardEngine(baselinePolicies())
  const d1 = engine.decide({ eventType: 'before_tool_call', data: { toolName: 'bash', command: 'cat ~/.ssh/id_rsa', protectedPathHit: '~/.ssh/id_rsa' }, context: {} })
  assert.equal(d1.action, 'block')
  const d2 = engine.decide({ eventType: 'before_tool_call', data: { toolName: 'bash', command: 'rm -rf /tmp/x', deleteOutsideWorkspace: true }, context: {} })
  assert.equal(d2.action, 'block')
})

test('baseline: loop hazard, artifact execution, exfil high/medium', () => {
  const engine = new GuardEngine(baselinePolicies())
  assert.equal(engine.decide({ eventType: 'before_tool_call', data: { toolName: 'bash', repeatExceeded: true }, context: {} }).action, 'block')
  assert.equal(engine.decide({ eventType: 'before_tool_call', data: { toolName: 'bash', artifactExecutionRisk: true }, context: {} }).action, 'block')
  assert.equal(engine.decide({ eventType: 'before_tool_call', data: { toolName: 'bash', exfilChain: 'high' }, context: {} }).action, 'block')
  assert.equal(engine.decide({ eventType: 'before_tool_call', data: { toolName: 'bash', exfilChain: 'medium' }, context: {} }).action, 'warn')
})

test('baseline: tool-result injection is blocked at post-execute', () => {
  const engine = new GuardEngine(baselinePolicies())
  const decision = engine.decide({
    eventType: 'tool_result_persist',
    data: { toolName: 'web_search', toolResultRisk: 'block' },
    context: {},
  })
  assert.equal(decision.action, 'block')
  assert.equal(decision.policyId, 'base-block-tool-result-injection')
})

test('baseline: soft weak-phrase-only injection is warned, not blocked (B4#8)', () => {
  const engine = new GuardEngine(baselinePolicies())
  const decision = engine.decide({
    eventType: 'tool_result_persist',
    data: { toolName: 'web_search', toolResultRisk: 'warn' },
    context: {},
  })
  assert.equal(decision.action, 'warn')
  assert.equal(decision.policyId, 'base-warn-tool-result-injection')
})

test('baseline: overlong command alone is warned, not blocked (B4#6)', () => {
  const engine = new GuardEngine(baselinePolicies())
  const decision = engine.decide({
    eventType: 'before_tool_call',
    data: { toolName: 'git', command: 'git commit -m ' + 'x'.repeat(10_100), overlong: true },
    context: {},
  })
  assert.equal(decision.action, 'warn')
  assert.equal(decision.policyId, 'base-warn-overlong-command')
})

test('baseline: benign call with no feature fields passes', () => {
  const engine = new GuardEngine(baselinePolicies())
  const decision = engine.decide({ eventType: 'before_tool_call', data: { toolName: 'bash', command: 'ls -la' }, context: {} })
  assert.equal(decision.action, 'allow')
})

test('baseline: user policy at priority 100 overrides baseline', () => {
  const engine = new GuardEngine([
    ...baselinePolicies(),
    { id: 'user-allow-bash', hooks: ['before_tool_call'], priority: 100, action: 'allow', message: 'user allows bash', rules: [{ field: 'toolName', operator: 'eq', value: 'bash' }] },
  ])
  const decision = engine.decide({ eventType: 'before_tool_call', data: { toolName: 'bash', command: 'rm -rf /', highRisk: true }, context: {} })
  assert.equal(decision.action, 'allow')
})

test('baseline: user intent attack is rejected at prompt build', () => {
  const engine = new GuardEngine(baselinePolicies())
  const decision = engine.decide({
    eventType: 'before_prompt_build',
    data: { content: 'disable the safety guard', userIntentRisk: 'block' },
    context: {},
  })
  assert.equal(decision.action, 'block')
  assert.equal(decision.policyId, 'base-block-user-intent-attack')
})

test('baseline: soft intent is warned', () => {
  const engine = new GuardEngine(baselinePolicies())
  const decision = engine.decide({
    eventType: 'before_prompt_build',
    data: { userIntentRisk: 'warn' },
    context: {},
  })
  assert.equal(decision.action, 'warn')
  assert.equal(decision.policyId, 'base-warn-user-intent-attack')
})

test('baseline: engine observe mode downgrades the whole table to warn', () => {
  const engine = new GuardEngine(baselinePolicies(), true, 'monitor')
  const decision = engine.decide({
    eventType: 'before_tool_call',
    data: { toolName: 'bash', command: 'rm -rf /', highRisk: true },
    context: {},
  })
  assert.equal(decision.action, 'warn')
  assert.equal(decision.monitorDowngraded, true)
})

// ---- Baseline policies merged from operator_rules.yml (2026-08-31) ----

test('baseline: command-threat block tier fires per family', () => {
  const engine = new GuardEngine(baselinePolicies())
  const cases = [
    ['base-block-privilege-escalation', { privEsc: 'block' }],
    ['base-block-system-path-write', { systemPathWrite: 'block' }],
    ['base-block-config-tamper', { configTamper: true }],
    ['base-block-sandbox-escape', { sandboxEscape: 'block' }],
  ]
  for (const [id, data] of cases) {
    const d = engine.decide({ eventType: 'before_tool_call', data: { toolName: 'bash', ...data }, context: {} })
    assert.equal(d.action, 'block', id)
    assert.equal(d.policyId, id, id)
  }
})

test('baseline: command-threat warn tier records without blocking', () => {
  const engine = new GuardEngine(baselinePolicies())
  const cases = [
    ['base-warn-privilege-escalation', { privEsc: 'warn' }],
    ['base-warn-system-path-write', { systemPathWrite: 'warn' }],
    ['base-warn-sandbox-escape', { sandboxEscape: 'warn' }],
    ['base-warn-net-recon', { netRecon: true }],
    ['base-warn-path-traversal', { pathTraversal: true }],
    ['base-warn-untrusted-source', { untrustedSource: true }],
    ['base-warn-insecure-registry', { insecureRegistry: true }],
    ['base-warn-secret-logging', { secretLogging: true }],
    ['base-warn-memory-poison-write', { memoryPoisonWrite: true }],
  ]
  for (const [id, data] of cases) {
    const d = engine.decide({ eventType: 'before_tool_call', data: { toolName: 'bash', ...data }, context: {} })
    assert.equal(d.action, 'warn', id)
    assert.equal(d.policyId, id, id)
  }
})
