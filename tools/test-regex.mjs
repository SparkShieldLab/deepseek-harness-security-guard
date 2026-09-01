// node:test suite for the `regex` operator (real RegExp matching).
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

test('regex: bare pattern matches substrings (unlike anchored glob)', () => {
  const e = new GuardEngine([policy([{ id: 'r', field: 'command', operator: 'regex', value: 'rm\\s+.*--no-preserve' }])])
  assert.equal(e.decide(toolEvent('rm -rf --no-preserve-root /')).action, 'block')
  assert.equal(e.decide(toolEvent('rm file.txt')).action, 'allow')
})

test('regex: ^ anchor works (matches start only)', () => {
  const e = new GuardEngine([policy([{ id: 'r', field: 'command', operator: 'regex', value: '^ls' }])])
  assert.equal(e.decide(toolEvent('ls -la')).action, 'block')
  assert.equal(e.decide(toolEvent('xls')).action, 'allow')
})

test('regex: /pattern/i literal form supports flags', () => {
  const e = new GuardEngine([policy([{ id: 'r', field: 'command', operator: 'regex', value: '/curl|wget/i' }])])
  assert.equal(e.decide(toolEvent('CURL -o x')).action, 'block', 'case-insensitive flag i')
  assert.equal(e.decide(toolEvent('git clone x')).action, 'allow')
})

test('regex: invalid pattern fails safe (no match, no throw)', () => {
  const e = new GuardEngine([policy([{ id: 'r', field: 'command', operator: 'regex', value: 'rm [' }])])
  assert.equal(e.decide(toolEvent('rm -rf /')).action, 'allow', 'invalid regex must not match')
})

test('regex: ReDoS shapes (a quantified group re-quantified) are rejected, not run', () => {
  // S1/N3: `(a?){40}` slips the earlier nested-quantifier check and freezes the
  // event loop on non-matching input; it must fail safe (match nothing).
  const e = new GuardEngine([policy([{ id: 'r', field: 'command', operator: 'regex', value: '^(a?){40}$' }])])
  const input = 'a'.repeat(20) + '!'
  const start = Date.now()
  assert.equal(e.decide(toolEvent(input)).action, 'allow', 'ReDoS pattern must be rejected')
  assert.ok(Date.now() - start < 2000, 'decision must not freeze the event loop')
})

test('regex: safe group repetitions are still evaluated', () => {
  // `(ab){40}` has no internal quantifier/alternation — linear, must still run.
  const e = new GuardEngine([policy([{ id: 'r', field: 'command', operator: 'regex', value: '(ab){40}$' }])])
  assert.equal(e.decide(toolEvent('ab'.repeat(40))).action, 'block')
  assert.equal(e.decide(toolEvent('ab'.repeat(39) + '!')).action, 'allow')
})

test('regex: nested-alternation ReDoS family is rejected, not run (S1 regress)', () => {
  // Round-5 S1 bypass: `((a+)|(b+))+` is catastrophic on 28 chars but slips
  // every regex-based heuristic (the inner `|` sits past the first `)`).
  // It must fail safe (match nothing) and must not freeze the loop.
  const bombs = [
    '((a+)|(b+))+$',
    '((a+)|b)+',
    '((a*)(b?))+',
    '(a+(b?))+',
    '(a+?)+',
    '(?:a+)+',
    '^((a?)+)$',
  ]
  for (const value of bombs) {
    const e = new GuardEngine([policy([{ id: 'r', field: 'command', operator: 'regex', value }])])
    const input = 'a'.repeat(30) + '!'
    const start = Date.now()
    assert.equal(e.decide(toolEvent(input)).action, 'allow', `${value} must be rejected as non-matching`)
    assert.ok(Date.now() - start < 2000, `${value} must not freeze the event loop`)
  }
})

test('regex: nested groups WITHOUT inner quantifiers still evaluate (no over-rejection)', () => {
  // These shapes are linear: nested groups with no ?+* inside, quantifier
  // chars inside character classes, or non-capturing modifiers.
  const e = new GuardEngine([policy([{ id: 'r', field: 'command', operator: 'regex', value: '((ab)(cd))+$' }])])
  assert.equal(e.decide(toolEvent('abcdabcd')).action, 'block')
  assert.equal(e.decide(toolEvent('abcdab')).action, 'allow')

  const e2 = new GuardEngine([policy([{ id: 'r', field: 'command', operator: 'regex', value: '(a[+*?])+$' }])])
  assert.equal(e2.decide(toolEvent('a?a*a+')).action, 'block', 'quantifier chars inside a class are literal')
  assert.equal(e2.decide(toolEvent('aaa')).action, 'allow')

  // A non-capturing modifier alone is not a quantifier: `(?:a)+` is linear.
  const e4 = new GuardEngine([policy([{ id: 'r', field: 'command', operator: 'regex', value: '(?:a)+$' }])])
  assert.equal(e4.decide(toolEvent('aaaa')).action, 'block')
  assert.equal(e4.decide(toolEvent('bbb')).action, 'allow')

  // Bounded repetition inside a group is linear and must stay evaluated.
  const e3 = new GuardEngine([policy([{ id: 'r', field: 'command', operator: 'regex', value: '(a{1,2}){40}$' }])])
  assert.equal(e3.decide(toolEvent('a'.repeat(40))).action, 'block')
  assert.equal(e3.decide(toolEvent('a'.repeat(20) + '!')).action, 'allow')
})

test('regex: works on non-command string fields (content)', () => {
  const promptPolicy = {
    id: 'p', hooks: ['before_prompt_build'], priority: 100, action: 'warn', message: '',
    rules: [{ id: 'r', field: 'content', operator: 'regex', value: 'BEGIN (RSA |EC )?PRIVATE KEY' }],
  }
  const e = new GuardEngine([promptPolicy])
  const ev = { eventType: 'before_prompt_build', content: '-----BEGIN RSA PRIVATE KEY-----', data: {}, context: {} }
  assert.equal(e.decide(ev).action, 'warn')
  assert.equal(e.decide({ eventType: 'before_prompt_build', content: 'hello world', data: {}, context: {} }).action, 'allow')
})

test('raw: matches the full event payload as JSON (contains + regex)', () => {
  const e = new GuardEngine([policy([{ id: 'r', field: 'raw', operator: 'contains', value: '"command":"rm -rf /"' }])])
  assert.equal(e.decide(toolEvent('rm -rf /')).action, 'block')
  assert.equal(e.decide(toolEvent('ls -la')).action, 'allow')

  const e2 = new GuardEngine([policy([{ id: 'r', field: 'raw', operator: 'regex', value: 'toolName.{0,20}bash' }])])
  const ev = { eventType: 'before_tool_call', data: { toolName: 'bash', command: 'ls' }, context: {} }
  assert.equal(e2.decide(ev).action, 'block')
})
