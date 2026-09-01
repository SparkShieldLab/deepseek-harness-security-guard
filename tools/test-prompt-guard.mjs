// node:test suite for the prompt-guard section builder (runs against lib/ after `npm run build`).
// Usage: npm run build && node --test tools/
import test from 'node:test'
import assert from 'node:assert/strict'
import {
  PROMPT_GUARD_MAX_CHARS,
  PROMPT_GUARD_RULES,
  buildPromptGuardSection,
  buildPromptGuardText,
  buildSessionRiskContext,
} from '../lib/prompt-guard.js'
import { GuardStateStore } from '../lib/state-store.js'

test('prompt-guard: static rules are always present', () => {
  const text = buildPromptGuardText(new GuardStateStore(), undefined)
  for (const rule of PROMPT_GUARD_RULES) assert.ok(text.includes(rule.slice(0, 24)))
  assert.ok(!text.includes('Session risk context'))
})

test('prompt-guard: risk context appears when flags/secrets exist', () => {
  const state = new GuardStateStore()
  state.noteRiskFlags('s1', ['persona-hijack-weak'])
  state.noteSecrets('s1', ['sk-abc'])
  const text = buildPromptGuardText(state, 's1')
  assert.ok(text.includes('Session risk context (session s1)'))
  assert.ok(text.includes('observed secrets in tool output this session: 1'))
  assert.ok(text.includes('persona-hijack-weak'))
})

test('prompt-guard: clean session has no risk block', () => {
  const ctx = buildSessionRiskContext(new GuardStateStore(), 's1')
  assert.equal(ctx, '')
})

test('prompt-guard: unknown session key falls back to rules-only text', () => {
  const state = new GuardStateStore()
  state.noteSecrets('other', ['sk-abc'])
  const text = buildPromptGuardText(state, undefined)
  assert.ok(!text.includes('Session risk context'))
})

test('prompt-guard: bounded length', () => {
  const text = buildPromptGuardText(new GuardStateStore(), undefined)
  assert.ok(text.length <= PROMPT_GUARD_MAX_CHARS)
  assert.ok(text.length > 200)
})

test('prompt-guard: section shape matches AssembledSection', () => {
  const section = buildPromptGuardSection(new GuardStateStore(), undefined)
  assert.equal(section.name, 'agent-security-guard')
  assert.equal(typeof section.text, 'string')
})
