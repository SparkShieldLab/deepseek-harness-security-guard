/**
 * Tests for the GuardPrefs schema (src/config.ts → lib/config.js), in
 * particular the legacy-storage compatibility of `modelReview.thinking`.
 *
 * The DSH settings service resolves a persisted namespace document through the
 * registered schema (`resolve = schema(base ∪ user section)`). After the
 * `thinking` flag upgraded from a boolean to a five-level enum, documents
 * written by older plugins still carry `thinking: true/false`, which made the
 * whole namespace validation throw at startup — every preference edit then
 * answered an error and silently rolled back on reload. These tests pin the
 * mapping (`true → 'medium'`, `false → 'default'`) exactly like the API-layer
 * patch validator in guard-api.ts.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { GuardPrefs } from '../lib/config.js'

/** Resolve like the settings service does: schema over the raw section. */
function resolve(section) {
  return GuardPrefs(section)
}

test('GuardPrefs: legacy boolean thinking archives resolve to the enum, not a throw', () => {
  const legacyTrue = resolve({ modelReview: { thinking: true } }).modelReview.thinking
  assert.equal(legacyTrue, 'medium', 'true maps to medium')
  const legacyFalse = resolve({ modelReview: { thinking: false } }).modelReview.thinking
  assert.equal(legacyFalse, 'default', 'false maps to default')
})

// ── timeoutMs: the legacy 3000 ms default migrates to 12000 on read ──

test('GuardPrefs: a persisted 3000 ms timeout (old default) migrates to 12000 on read', () => {
  assert.equal(resolve({ modelReview: { timeoutMs: 3000 } }).modelReview.timeoutMs, 12000, 'old default bumped')
})

test('GuardPrefs: a missing timeoutMs defaults to 12000', () => {
  assert.equal(resolve({}).modelReview.timeoutMs, 12000)
  assert.equal(resolve({ modelReview: {} }).modelReview.timeoutMs, 12000)
})

test('GuardPrefs: non-legacy timeout values pass through untouched', () => {
  assert.equal(resolve({ modelReview: { timeoutMs: 3001 } }).modelReview.timeoutMs, 3001, 'a deliberate ~3 s survives')
  assert.equal(resolve({ modelReview: { timeoutMs: 30000 } }).modelReview.timeoutMs, 30000)
  assert.equal(resolve({ modelReview: { timeoutMs: 60000 } }).modelReview.timeoutMs, 60000)
})

test('GuardPrefs: legacy boolean thinking survives a full document resolve for the engine read path', () => {
  // A real persisted section like ~/.dsh/settings.yaml after the enum upgrade.
  const legacyDocument = {
    locale: 'auto',
    guardEnabled: true,
    recordAllow: true,
    rulesEnabled: true,
    modelReview: {
      enabled: true,
      mode: 'custom',
      hooks: { beforeToolCall: true, toolResultPersist: true, afterToolCall: true, beforePromptBuild: true },
      prompt: 'custom template {content}',
      baseUrl: 'http://localhost/v1',
      apiKey: '',
      model: 'reviewer',
      timeoutMs: 30000,
      thinking: false,
    },
  }
  let resolved
  assert.doesNotThrow(() => { resolved = resolve(legacyDocument) })
  assert.equal(resolved.modelReview.thinking, 'default')
  assert.equal(resolved.modelReview.mode, 'custom')
  assert.equal(resolved.modelReview.enabled, true)
  assert.equal(resolved.modelReview.timeoutMs, 30000)
  // Legacy `hooks` + `prompt` are un-declared passthrough fields: they survive
  // schema validation untouched but the engine ignores them (the review chain
  // reads baselineTemplates + templates only).
  assert.equal(resolved.modelReview.prompt, 'custom template {content}', 'legacy prompt passes through')
})

test('GuardPrefs: the baseline is the shipped three templates; absent → schema default', () => {
  const resolved = resolve({})
  const ids = resolved.modelReview.baselineTemplates.map((b) => b.id)
  assert.deepEqual(ids, ['malicious-intent-detection', 'risk-instruction-detection', 'intent-drift-detection'])
  assert.deepEqual(resolved.modelReview.templates, [])
  // A persisted enabled=false on one card survives resolve.
  const patched = resolve({
    modelReview: {
      baselineTemplates: resolved.modelReview.baselineTemplates.map((b) =>
        b.id === 'intent-drift-detection' ? { ...b, enabled: false } : b),
    },
  })
  assert.equal(patched.modelReview.baselineTemplates.find((b) => b.id === 'intent-drift-detection')?.enabled, false)
})

test('GuardPrefs: current string enum values pass through unchanged', () => {
  for (const value of ['default', 'off', 'low', 'medium', 'high']) {
    assert.equal(resolve({ modelReview: { thinking: value } }).modelReview.thinking, value, `${value} stays verbatim`)
  }
})

test('GuardPrefs: documents missing thinking still default to the enum default', () => {
  assert.equal(resolve({}).modelReview.thinking, 'default')
  assert.equal(resolve({ modelReview: { enabled: true } }).modelReview.thinking, 'default')
})

test('GuardPrefs: an out-of-enum string is still rejected (fail-loud, nothing silently maps)', () => {
  assert.throws(() => resolve({ modelReview: { thinking: 'very-high' } }))
})