// node:test suite for glob wildcard matching on string fields (command/toolName).
// Usage: node --test tools/
import test from 'node:test'
import assert from 'node:assert/strict'
import { GuardEngine } from '../lib/engine.js'

const policy = (rules, action = 'block') => ({
  id: 'p', hooks: ['before_tool_call'], priority: 100, action,
  message: '', rules,
})

const toolEvent = (command) => ({
  eventType: 'before_tool_call',
  data: { command },
  context: {},
})

test('wildcard: ls* matches ls with any arguments', () => {
  const e = new GuardEngine([policy([{ id: 'r', field: 'command', operator: 'matches', value: 'ls*' }])])
  for (const cmd of ['ls', 'ls -la', 'ls -la /home/mjli25', 'ls -R /etc']) {
    const v = e.decide(toolEvent(cmd))
    assert.equal(v.action, 'block', `${cmd} should match ls*`)
  }
  assert.equal(e.decide(toolEvent('cat /etc/passwd')).action, 'allow', 'cat does not match ls*')
})

test('wildcard: command is the full raw string (not just the binary name)', () => {
  const e = new GuardEngine([policy([{ id: 'r', field: 'command', operator: 'matches', value: 'ls*' }])])
  // `ls*` anchors at the start: ^ls.*$ — a command that starts differently must not match
  assert.equal(e.decide(toolEvent('xls')).action, 'allow', 'xls does not match ls*')
  assert.equal(e.decide(toolEvent(' ls -la')).action, 'allow', 'leading-space command does not match ls*')
})

test('wildcard: write* on toolName (baseline ask-on-writes pattern)', () => {
  const e = new GuardEngine([policy([{ id: 'r', field: 'toolName', operator: 'matches', value: 'write*' }])])
  const ev = (toolName) => ({ eventType: 'before_tool_call', data: { toolName }, context: {} })
  assert.equal(e.decide(ev('write_file')).action, 'block')
  assert.equal(e.decide(ev('write_json')).action, 'block')
  assert.equal(e.decide(ev('read_file')).action, 'allow')
})

test('wildcard: matches escapes regex metacharacters except *', () => {
  const e = new GuardEngine([policy([{ id: 'r', field: 'command', operator: 'matches', value: 'rm -rf*' }])])
  // the '.' in 'rm -rf*' must be literal (anchored ^rm -rf.*$)
  assert.equal(e.decide(toolEvent('rm -rf /')).action, 'block')
  assert.equal(e.decide(toolEvent('rm -rxf /')).action, 'allow', 'x must not be wildcard')
})
