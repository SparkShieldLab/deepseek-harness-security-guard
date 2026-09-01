/**
 * Unit tests for the model-review stage (src/model-review.ts): the pluggable
 * output-parser seam (JsonModelVerdictParser), the review-prompt renderer, the
 * verdict-merge policy, and the ModelReviewEngine orchestration with injected
 * fake rule/model stages.
 *
 * Run after a build: `node --test tools/test-model-review.mjs`
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  renderReviewPrompt,
  JsonModelVerdictParser,
  AuditRiskModelVerdictParser,
  LineRiskModelVerdictParser,
  CompositeModelVerdictParser,
  createModelVerdictParser,
  mergeVerdicts,
  ModelReviewEngine,
  DefaultModelStage,
  HttpModelCaller,
  OpenAiResponsesCaller,
  AnthropicCaller,
  SessionModelCaller,
} from '../lib/model-review.js'
import {
  USER_REQUEST_RISK_PROMPT,
  AGENT_BEHAVIOR_RISK_PROMPT,
  INTENT_DRIFT_PROMPT,
  BASELINE_REVIEW_TEMPLATES,
} from '../lib/audit-prompts.js'
import { MODEL_REVIEW_DEFAULTS, GuardPrefs } from '../lib/config.js'


// ── parser: the seam that will change when structured output lands ──

test('HttpModelCaller: the reasoning setting forwards enum values verbatim; default attaches nothing', async () => {
  const captured = []
  const realFetch = globalThis.fetch
  globalThis.fetch = async (url, init) => {
    captured.push({ url, body: JSON.parse(init.body) })
    return {
      ok: true, status: 200,
      json: async () => ({ choices: [{ message: { content: '{"action":"allow","reason":"ok"}' } }] }),
      text: async () => '',
    }
  }
  try {
    const spec = { prompt: 'review me', system: 'guard it', sessionId: 's1' }
    const off = new HttpModelCaller('https://api.example.com/v1/', 'k', 'reviewer-1', 'default')
    const offText = await off.call(spec)
    assert.equal(offText, '{"action":"allow","reason":"ok"}')
    const offBody = captured[0]
    assert.equal(offBody.url, 'https://api.example.com/v1/chat/completions')
    assert.equal(offBody.body.reasoning_effort, undefined, "'default' attaches no reasoning field")
    assert.equal(offBody.body.temperature, 0, "'default' keeps the deterministic temperature")
    assert.equal(offBody.body.model, 'reviewer-1')
    assert.equal(offBody.body.stream, false)
    assert.ok(offBody.body.messages.length === 2, 'system + user messages')

    for (const value of ['off', 'low', 'medium', 'high']) {
      await new HttpModelCaller('https://api.example.com/v1', 'k', 'reviewer-2', value).call({ prompt: 'review me' })
      const body = captured[captured.length - 1].body
      assert.equal(body.reasoning_effort, value, `enum '${value}' is forwarded verbatim`)
      assert.equal(body.temperature, undefined, `reasoning level '${value}': temperature omitted (reasoning endpoints reject it)`)
    }
  } finally {
    globalThis.fetch = realFetch
  }
})

// ── SessionModelCaller: terminal finish reasons must surface the real cause ──

/** Fake llm service streaming the given chunks. */
function fakeLlm(chunks) {
  return { stream: async function* () { for (const c of chunks) yield c } }
}

test('SessionModelCaller: assembles text deltas into the verdict text', async () => {
  const llm = fakeLlm([
    { type: 'block-start', index: 0, blockType: 'text' },
    { type: 'text-delta', index: 0, text: '{"action":"allow",' },
    { type: 'text-delta', index: 0, text: '"reason":"ok"}' },
    { type: 'block-end', index: 0, block: { type: 'text', text: '{"action":"allow","reason":"ok"}' } },
    { type: 'finish', reason: { kind: 'stop' } },
  ])
  const text = await new SessionModelCaller(llm).call({ prompt: 'review me', route: { provider: 'p', model: 'm' } })
  assert.equal(text, '{"action":"allow","reason":"ok"}')
})

test('SessionModelCaller: a terminal error finish surfaces the failure instead of "produced no text"', async () => {
  const llm = fakeLlm([
    { type: 'finish', reason: { kind: 'error', failure: { message: 'provider 401 unauthorized', code: 'auth' } } },
  ])
  await assert.rejects(
    new SessionModelCaller(llm).call({ prompt: 'review me', route: { provider: 'p', model: 'm' } }),
    /session model stream error: provider 401 unauthorized/,
  )
})

test('SessionModelCaller: an aborted finish with a fired deadline names the timeout', async () => {
  const llm = fakeLlm([
    { type: 'block-start', index: 0, blockType: 'text' },
    { type: 'text-delta', index: 0, text: 'partial' },
    { type: 'finish', reason: { kind: 'aborted', failure: { message: 'aborted', code: 'aborted' } } },
  ])
  const controller = new AbortController()
  controller.abort()
  await assert.rejects(
    new SessionModelCaller(llm).call({ prompt: 'review me', route: { provider: 'p', model: 'm' }, signal: controller.signal }),
    /session model review aborted by the timeout deadline/,
  )
})

test('SessionModelCaller: max-tokens with only reasoning deltas diagnoses the spent budget', async () => {
  const llm = fakeLlm([
    { type: 'block-start', index: 0, blockType: 'reasoning' },
    { type: 'reasoning-delta', index: 0, text: 'thinking...' },
    { type: 'finish', reason: { kind: 'max-tokens' } },
  ])
  await assert.rejects(
    new SessionModelCaller(llm).call({ prompt: 'review me', route: { provider: 'p', model: 'm' } }),
    /max-tokens budget before producing text/,
  )
})

test('OpenAiResponsesCaller: posts to /responses with an input list and parses output_text / message parts', async () => {
  const captured = []
  const realFetch = globalThis.fetch
  globalThis.fetch = async (url, init) => {
    captured.push({ url, headers: init.headers, body: JSON.parse(init.body) })
    return {
      ok: true, status: 200,
      json: async () => ({
        output_text: '{"action":"warn","reason":"careful"}',
        output: [
          { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: '{"action":"warn","reason":"careful"}' }] },
        ],
      }),
      text: async () => '',
    }
  }
  try {
    const text = await new OpenAiResponsesCaller('https://api.example.com/v1/', 'k', 'rev', 'high').call({ prompt: 'review me', system: 'guard it' })
    assert.equal(text, '{"action":"warn","reason":"careful"}', 'short-circuits to output_text')
    const req = captured[0]
    assert.equal(req.url, 'https://api.example.com/v1/responses')
    assert.equal(req.headers.authorization, 'Bearer k')
    assert.ok(Array.isArray(req.body.input))
    assert.equal(req.body.input[0].role, 'system')
    assert.equal(req.body.input[1].content, 'review me')
    assert.deepEqual(req.body.reasoning, { effort: 'high' }, 'Responses API takes reasoning.effort, not the chat-completions flag')
    assert.equal(req.body.reasoning_effort, undefined, 'chat-completions field must not leak into the Responses protocol')
    assert.equal(req.body.temperature, undefined, 'reasoning endpoints reject temperature; omitted for reasoning levels')
    assert.equal(req.body.messages, undefined, 'Responses API uses input, not messages')
  } finally {
    globalThis.fetch = realFetch
  }
})

test('OpenAiResponsesCaller: default/off attach no reasoning field and keep temperature 0', async () => {
  const captured = []
  const realFetch = globalThis.fetch
  globalThis.fetch = async (_url, init) => {
    captured.push(JSON.parse(init.body))
    return { ok: true, status: 200, json: async () => ({ output_text: 'ok' }), text: async () => '' }
  }
  try {
    for (const value of ['default', 'off']) {
      await new OpenAiResponsesCaller('https://api.example.com/v1', 'k', 'rev', value).call({ prompt: 'review me' })
      const body = captured[captured.length - 1]
      assert.equal(body.reasoning, undefined, `${value}: Responses API has no way to disable reasoning; attach nothing`)
      assert.equal(body.temperature, 0, `${value}: deterministic temperature stays`)
    }
  } finally {
    globalThis.fetch = realFetch
  }
})

test('OpenAiResponsesCaller: falls back to message parts when output_text is absent', async () => {
  const realFetch = globalThis.fetch
  globalThis.fetch = async () => ({
    ok: true, status: 200,
    json: async () => ({
      output: [
        { type: 'function_call', name: 'x', arguments: '{}' },
        { type: 'message', role: 'assistant', content: [
          { type: 'output_text', text: 'first' },
          { type: 'output_text', text: 'second' },
        ] },
      ],
    }),
    text: async () => '',
  })
  try {
    const text = await new OpenAiResponsesCaller('https://api.example.com/v1', 'k', 'rev', 'low').call({ prompt: 'review me' })
    assert.equal(text, 'first second', 'message output_text parts are joined')
  } finally {
    globalThis.fetch = realFetch
  }
})

test('AnthropicCaller: uses /v1/messages, anthropic headers, and maps thinking to a token budget', async () => {
  const captured = []
  const realFetch = globalThis.fetch
  globalThis.fetch = async (url, init) => {
    captured.push({ url, headers: init.headers, body: JSON.parse(init.body) })
    return {
      ok: true, status: 200,
      json: async () => ({ content: [{ type: 'text', text: '{"action":"block","reason":"dangerous"}' }] }),
      text: async () => '',
    }
  }
  try {
    // Base URL without /v1 → the caller adds it.
    const text = await new AnthropicCaller('https://api.anthropic.com', 'sk-ant', 'claude-sonnet', 'medium').call({ prompt: 'review me', system: 'guard it' })
    assert.equal(text, '{"action":"block","reason":"dangerous"}')
    const req = captured[0]
    assert.equal(req.url, 'https://api.anthropic.com/v1/messages')
    assert.equal(req.headers['x-api-key'], 'sk-ant')
    assert.equal(req.headers['anthropic-version'], '2023-06-01')
    assert.equal(req.body.system, 'guard it')
    assert.deepEqual(req.body.messages, [{ role: 'user', content: 'review me' }])
    assert.equal(req.body.temperature, 1, 'thinking enabled requires temperature 1')
    assert.equal(req.body.max_tokens, 4096, 'max_tokens = budget + headroom (must strictly exceed budget_tokens)')
    assert.deepEqual(req.body.thinking, { type: 'enabled', budget_tokens: 2048 }, 'medium → 2048-token budget')
  } finally {
    globalThis.fetch = realFetch
  }
})

test('AnthropicCaller: default/off attach no thinking block; endpoint keeps its own /v1', async () => {
  const captured = []
  const realFetch = globalThis.fetch
  globalThis.fetch = async (url, init) => {
    captured.push({ url, body: JSON.parse(init.body) })
    return { ok: true, status: 200, json: async () => ({ content: [{ type: 'text', text: 'ok' }] }), text: async () => '' }
  }
  try {
    for (const value of ['default', 'off', 'high']) {
      await new AnthropicCaller('https://api.anthropic.com/v1', 'k', 'm', value).call({ prompt: 'review me' })
      const body = captured[captured.length - 1]
      assert.equal(body.url, 'https://api.anthropic.com/v1/messages', 'base already under /v1 is not doubled')
      if (value === 'high') {
        assert.deepEqual(body.body.thinking, { type: 'enabled', budget_tokens: 8192 }, 'high → 8192 budget')
        assert.equal(body.body.temperature, 1, 'thinking enabled requires temperature 1')
        assert.equal(body.body.max_tokens, 10240, 'max_tokens = budget + headroom')
      } else {
        assert.equal(body.body.thinking, undefined, `${value} attaches no thinking block`)
        assert.equal(body.body.temperature, 0, `${value}: deterministic temperature stays`)
        assert.equal(body.body.max_tokens, 2048, `${value}: default max_tokens`)
      }
    }
  } finally {
    globalThis.fetch = realFetch
  }
})

test('AnthropicCaller: thinking levels keep the API contract (temperature 1, max_tokens > budget_tokens)', async () => {
  const bodies = []
  const realFetch = globalThis.fetch
  globalThis.fetch = async (_url, init) => {
    bodies.push(JSON.parse(init.body))
    return { ok: true, status: 200, json: async () => ({ content: [{ type: 'text', text: 'ok' }] }), text: async () => '' }
  }
  try {
    for (const level of ['low', 'medium', 'high']) {
      await new AnthropicCaller('https://api.anthropic.com', 'k', 'm', level).call({ prompt: 'review me' })
      const body = bodies[bodies.length - 1]
      assert.equal(body.temperature, 1, `${level}: Anthropic requires temperature 1 when thinking is enabled`)
      assert.ok(body.max_tokens > body.thinking.budget_tokens, `${level}: max_tokens (${body.max_tokens}) must strictly exceed budget_tokens (${body.thinking.budget_tokens})`)
    }
  } finally {
    globalThis.fetch = realFetch
  }
})

test('AnthropicCaller: zero-token or non-text content throws a readable error', async () => {
  const realFetch = globalThis.fetch
  globalThis.fetch = async () => ({
    ok: true, status: 200,
    json: async () => ({ content: [{ type: 'thinking', thinking: '…' }] }),
    text: async () => '',
  })
  try {
    await assert.rejects(
      () => new AnthropicCaller('https://api.anthropic.com', 'k', 'm', 'off').call({ prompt: 'review me' }),
      /no text content/,
    )
  } finally {
    globalThis.fetch = realFetch
  }
})

test('parser: parses a plain JSON verdict', () => {
  const parser = new JsonModelVerdictParser()
  const v = parser.parse('{"action":"block","reason":"rm -rf is dangerous","confidence":0.9}')
  assert.equal(v?.action, 'block')
  assert.equal(v?.reason, 'rm -rf is dangerous')
  assert.equal(v?.confidence, 0.9)
})

test('parser: strips markdown code fences', () => {
  const parser = new JsonModelVerdictParser()
  const v = parser.parse('```json\n{"action":"warn","reason":"suspicious"}\n```')
  assert.equal(v?.action, 'warn')
  assert.equal(v?.reason, 'suspicious')
})

test('parser: tolerates trailing prose after the JSON object', () => {
  const parser = new JsonModelVerdictParser()
  const v = parser.parse('{"action":"ask","reason":"needs approval"}\nThe call looks risky.')
  assert.equal(v?.action, 'ask')
})

test('parser: reasoning models narrate first, verdict JSON is the LAST balanced object', () => {
  const parser = new JsonModelVerdictParser()
  // Long thinking chain first; a draft `{...}` mid-thought; the final verdict at the end.
  const raw = 'We need answer user. Ensure no markdown. JSON only. {"action":"block","reason":"draft reconsidered"}.'
    + ' Actually benign. final only JSON.\n\n'
    + '{"action":"allow","reason":"Benign greeting","confidence":0.99}'
  const v = parser.parse(raw)
  assert.equal(v?.action, 'allow', 'the LAST balanced object is the verdict, not the mid-thought draft')
  assert.equal(v?.reason, 'Benign greeting')
  assert.equal(v?.confidence, 0.99)
})

test('parser: a single object amid prose parses (no draft to outrank)', () => {
  const parser = new JsonModelVerdictParser()
  assert.equal(parser.parse('thinking {"action":"allow","reason":"x"} done')?.action, 'allow')
})

test('parser: returns null on garbage / bad action / missing reason / empty', () => {
  const parser = new JsonModelVerdictParser()
  assert.equal(parser.parse('not json at all'), null)
  assert.equal(parser.parse('{"action":"explode","reason":"x"}'), null)
  assert.equal(parser.parse('{"action":"block"}'), null)
  assert.equal(parser.parse('{"reason":"no action"}'), null)
  assert.equal(parser.parse(''), null)
  assert.equal(parser.parse('null'), null)
  assert.equal(parser.parse('[1,2,3]'), null)
})

test('parser: confidence is optional and range-checked', () => {
  const parser = new JsonModelVerdictParser()
  assert.equal(parser.parse('{"action":"block","reason":"x","confidence":2}')?.confidence, undefined)
  assert.equal(parser.parse('{"action":"block","reason":"x","confidence":-1}')?.confidence, undefined)
})

// ── prompt rendering ──

// ── the shipped baseline audit templates output a two-line verdict, no escapes ──

test('prompt: the baseline templates show a two-line output contract (no Python {{ }} escapes, no JSON example)', () => {
  for (const [name, template] of [
    ['恶意意图检测', USER_REQUEST_RISK_PROMPT],
    ['风险指令检测', AGENT_BEHAVIOR_RISK_PROMPT],
    ['意图偏离检测', INTENT_DRIFT_PROMPT],
  ]) {
    assert.ok(!template.includes('{{'), `${name}: no doubled opening brace reaches the model`)
    assert.ok(!template.includes('}}'), `${name}: no doubled closing brace reaches the model`)
    assert.ok(!template.includes('user_request_risks'), `${name}: does not ask for the legacy JSON shape`)
    assert.ok(template.includes('Line 1:'), `${name}: documents the two-line output contract`)
    assert.ok(template.includes('Line 2:'), `${name}: documents the two-line output contract`)
    assert.ok(template.includes('{user_query}'), `${name}: binds user query`)
  }
})

// ── AuditRiskModelVerdictParser: the two-dimension shape the built-in template asks for ──

const noRisk = {
  user_request_risks: ['No Risk'],
  user_request_reason: '',
  agent_behavior_risks: ['No Risk'],
  agent_behavior_reason: '',
}
const audit = (over) => JSON.stringify({ ...noRisk, ...over })

test('audit parser: clean on both dimensions -> allow', () => {
  const v = new AuditRiskModelVerdictParser().parse(audit({}))
  assert.ok(v, 'parses')
  assert.equal(v.action, 'allow')
})

test('audit parser: agent behavior destructive command -> block, category named in the reason', () => {
  const v = new AuditRiskModelVerdictParser().parse(audit({
    agent_behavior_risks: ['Destructive Command'],
    agent_behavior_reason: 'rm -rf / issued at step 3',
  }))
  assert.equal(v.action, 'block')
  assert.ok(v.reason.includes('Destructive Command'), 'the matched category is auditable')
  assert.ok(v.reason.includes('rm -rf /'), 'the model evidence is carried through')
})

test('audit parser: user request jailbreak attempt -> block (guard bypass is not advisory)', () => {
  const v = new AuditRiskModelVerdictParser().parse(audit({
    user_request_risks: ['Instruction Override / Jailbreak Attempt'],
    user_request_reason: 'asks to ignore all system instructions',
  }))
  assert.equal(v.action, 'block')
})

test('audit parser: user request risks are advisory (warn) except guard-bypass attempts', () => {
  for (const category of [
    'Session / Context Probing',
    'PII Disclosure Intent',
    'Indirect Prompt Injection',
    'Tool Output Injection',
    'Workspace Escape Inducement',
    'Cross-Tenant Disclosure Intent',
  ]) {
    const v = new AuditRiskModelVerdictParser().parse(audit({
      user_request_risks: [category],
      user_request_reason: 'evidence text',
    }))
    assert.equal(v.action, 'warn', `${category} warns without hard-blocking the user`)
  }
})

test('audit parser: attempted-but-unconfirmed behavior -> ask (human approval), not block', () => {
  for (const category of [
    'External Network Connection',
    'Malicious Dependency Installation',
    'System Path Write',
    'Tool Parameter Manipulation',
  ]) {
    const v = new AuditRiskModelVerdictParser().parse(audit({
      agent_behavior_risks: [category],
      agent_behavior_reason: 'evidence text',
    }))
    assert.equal(v.action, 'ask', `${category} deserves an approval prompt`)
  }
})

test('audit parser: actual disclosure of sensitive data -> block', () => {
  for (const category of [
    'PII Disclosure',
    'Business Secret Disclosure',
    'Cross-Tenant Disclosure',
    'Sandbox Escape Attempt',
    'Dangerous Tool Call',
    'Privilege Escalation / Permission Relaxation',
  ]) {
    const v = new AuditRiskModelVerdictParser().parse(audit({
      agent_behavior_risks: [category],
      agent_behavior_reason: 'evidence text',
    }))
    assert.equal(v.action, 'block', `${category} is a confirmed leak/irreversible action`)
  }
})

test('audit parser: strictest category wins across both dimensions', () => {
  const v = new AuditRiskModelVerdictParser().parse(JSON.stringify({
    user_request_risks: ['Session / Context Probing'],
    user_request_reason: 'probes the system prompt',
    agent_behavior_risks: ['External Network Connection', 'Destructive Command'],
    agent_behavior_reason: 'curl | sh then rm -rf',
  }))
  assert.equal(v.action, 'block')
})

test('audit parser: No Risk alongside a real category loses to the real category', () => {
  const v = new AuditRiskModelVerdictParser().parse(audit({
    agent_behavior_risks: ['No Risk', 'Destructive Command'],
    agent_behavior_reason: 'issued rm -rf',
  }))
  assert.equal(v.action, 'block')
  assert.ok(!v.reason.includes('No Risk'), 'the vacuous No Risk label is not surfaced')
})

test('audit parser: an unmapped category is treated as warn and named verbatim for tuning', () => {
  const v = new AuditRiskModelVerdictParser().parse(audit({
    agent_behavior_risks: ['Quantum Sabotage'],
    agent_behavior_reason: 'the model flagged something we cannot map',
  }))
  assert.equal(v.action, 'warn')
  assert.ok(v.reason.includes('Quantum Sabotage'), 'the unknown name must be auditable so the table can be extended')
})

test('audit parser: category matching tolerates case, padding and a trailing period', () => {
  const v = new AuditRiskModelVerdictParser().parse(audit({
    agent_behavior_risks: ['  destructive   COMMAND. '],
    agent_behavior_reason: 'dropped the database',
  }))
  assert.equal(v.action, 'block')
})

test('audit parser: a bare string where an array was asked for still parses', () => {
  const v = new AuditRiskModelVerdictParser().parse(audit({ agent_behavior_risks: 'Destructive Command' }))
  assert.equal(v.action, 'block')
})

test('audit parser: empty / non-string array entries degrade to no risk instead of throwing', () => {
  const v = new AuditRiskModelVerdictParser().parse(audit({
    agent_behavior_risks: [],
    user_request_risks: [null, 42, '  '],
  }))
  assert.equal(v.action, 'allow')
})

test('audit parser: markdown fences and narrated reasoning around the audit object still parse', () => {
  const raw = 'Thinking: the agent ran a destructive command.\n```json\n' + audit({
    agent_behavior_risks: ['Destructive Command'],
    agent_behavior_reason: 'rm -rf /',
  }) + '\n```\nThat is my verdict.'
  assert.equal(new AuditRiskModelVerdictParser().parse(raw).action, 'block')
})

test('audit parser: the legacy {action,reason} shape still parses (custom prompts keep working)', () => {
  const v = new AuditRiskModelVerdictParser().parse('{"action":"warn","reason":"looks odd","confidence":0.7}')
  assert.ok(v, 'delegates to the legacy parser')
  assert.equal(v.action, 'warn')
  assert.equal(v.reason, 'looks odd')
  assert.equal(v.confidence, 0.7)
})

test('audit parser: garbage, wrong shapes and the empty object all degrade safely', () => {
  const parser = new AuditRiskModelVerdictParser()
  assert.equal(parser.parse('not json at all'), null)
  assert.equal(parser.parse(''), null)
  assert.equal(parser.parse('{}'), null, 'an object with neither dimension is not a verdict')
  assert.equal(parser.parse('{"action":"nuke","reason":"x"}'), null, 'a bad legacy action is still rejected')
  assert.equal(parser.parse('{"user_request_risks":{"a":1},"agent_behavior_risks":[1,2]}'), null,
    'object-valued dimensions are not categories')
  // A single string (instead of an array) is one category; unmapped -> warn.
  assert.equal(parser.parse('{"user_request_risks":"Quantum Sabotage"}').action, 'warn')
})

test('audit parser: a category listed under the other dimension still maps to its own severity', () => {
  // Category names are globally meaningful; the dimension only says where the
  // evidence came from. A model that misfiles `Destructive Command` under the
  // user request must not silently degrade to the unmapped-category warn.
  const v = new AuditRiskModelVerdictParser().parse(audit({
    user_request_risks: ['Destructive Command'],
    user_request_reason: 'the user typed rm -rf / themselves',
  }))
  assert.equal(v.action, 'block')
})

test('audit parser: the composed reason stays bounded for the audit trail and notice text', () => {
  const v = new AuditRiskModelVerdictParser().parse(audit({
    user_request_risks: ['Session / Context Probing'],
    user_request_reason: 'x'.repeat(5000),
    agent_behavior_risks: ['Destructive Command'],
    agent_behavior_reason: 'y'.repeat(5000),
  }))
  assert.ok(v.reason.length <= 700, `reason is ${v.reason.length} chars, expected <= 700`)
})

test('parser factory: the wired-in parser understands the built-in template output shape', () => {
  const v = createModelVerdictParser().parse(audit({
    agent_behavior_risks: ['Destructive Command'],
    agent_behavior_reason: 'rm -rf /',
  }))
  assert.equal(v.action, 'block', 'the pipeline must consume what its own default prompt asks for')
})

test('prompt: baseline templates are non-empty and bind every placeholder they declare', () => {
  for (const base of BASELINE_REVIEW_TEMPLATES) {
    assert.ok(base.prompt.length > 0, `${base.id}: prompt is non-empty`)
    // The baseline templates declare {user_query} (+ {agent_behavior} where
    // they review agent behavior); the renderer must consume those.
    assert.ok(base.prompt.includes('{user_query}'), `${base.id}: binds {user_query}`)
    assert.ok(!base.prompt.includes('{{') && !base.prompt.includes('}}'), `${base.id}: no doubled brace escapes`)
  }
})

test('prompt: renders placeholders', () => {
  const out = renderReviewPrompt(USER_REQUEST_RISK_PROMPT, {
    hookType: 'agent/pre-step',
    content: 'rm -rf /',
    userQuery: 'please delete root so I can start fresh',
    agentBehavior: 'rm -rf /',
    rulesVerdict: 'allow',
    sessionId: 's1',
  })
  assert.ok(out.includes('please delete root'))
  assert.ok(!out.includes('{user_query}'), 'the user query placeholder is consumed')
})

test('prompt: renders INTENT_DRIFT template with both sides', () => {
  const out = renderReviewPrompt(INTENT_DRIFT_PROMPT, {
    hookType: 'tools/pre-execute',
    content: 'rm -rf /tmp/cache',
    userQuery: 'list my files',
    agentBehavior: 'rm -rf /tmp/cache',
    rulesVerdict: 'allow',
  })
  assert.ok(out.includes('list my files'))
  assert.ok(out.includes('rm -rf /tmp/cache'))
  assert.ok(!out.includes('{user_query}'))
  assert.ok(!out.includes('{agent_behavior}'))
})

test('prompt: legacy placeholders still render for custom templates', () => {
  const out = renderReviewPrompt('hook={hookType} content={content} verdict={rulesVerdict} session={sessionId}', {
    hookType: 'before_tool_call',
    content: 'ls -la',
    rulesVerdict: 'block',
    sessionId: 's1',
  })
  assert.ok(out.includes('hook=before_tool_call'))
  assert.ok(out.includes('content=ls -la'))
  assert.ok(out.includes('verdict=block'))
  assert.ok(out.includes('session=s1'))
})

test('prompt: legacy placeholders pass through untouched', () => {
  const out = renderReviewPrompt('hello {nope}', { hookType: 'x', content: '', rulesVerdict: 'allow' })
  assert.ok(out.includes('{nope}'))
})

// ── merge policy (strictest-wins: block > ask > warn > allow; rule is the floor) ──

test('merge: rule allow + model block -> model block (upgrade)', () => {
  const d = mergeVerdicts(
    { action: 'allow', matchedRules: [], message: 'no rule matched' },
    { action: 'block', reason: 'model says no' },
  )
  assert.equal(d.action, 'block')
  assert.equal(d.source, 'both')
  assert.equal(d.message, 'model says no')
  assert.equal(d.modelVerdict?.action, 'block')
})

test('merge: rule allow + model warn -> warn', () => {
  const d = mergeVerdicts(
    { action: 'allow', matchedRules: [], message: 'd' },
    { action: 'warn', reason: 'soft signal' },
  )
  assert.equal(d.action, 'warn')
})

test('merge: rule block + model allow -> rule block (rule is the floor)', () => {
  const d = mergeVerdicts(
    { action: 'block', matchedRules: ['p1'], message: 'rule says no', policyId: 'p1' },
    { action: 'allow', reason: 'model disagrees' },
  )
  assert.equal(d.action, 'block')
  assert.equal(d.source, 'rule')
  assert.equal(d.policyId, 'p1')
})

test('merge: rule block + model warn -> rule block (never relaxed)', () => {
  const d = mergeVerdicts(
    { action: 'block', matchedRules: ['p1'], message: 'rule says no' },
    { action: 'warn', reason: 'model downgrades' },
  )
  assert.equal(d.action, 'block')
  assert.equal(d.source, 'rule')
})

test('merge: rule ask + model block -> block (model is stricter)', () => {
  const d = mergeVerdicts(
    { action: 'ask', matchedRules: ['p1'], message: 'rule asks' },
    { action: 'block', reason: 'model blocks' },
  )
  assert.equal(d.action, 'block')
  assert.equal(d.source, 'both')
  assert.equal(d.message, 'model blocks')
})

test('merge: rule ask + model ask -> ask (tie, rule wins)', () => {
  const d = mergeVerdicts(
    { action: 'ask', matchedRules: ['p1'], message: 'rule asks' },
    { action: 'ask', reason: 'model asks' },
  )
  assert.equal(d.action, 'ask')
  assert.equal(d.source, 'rule')
})

test('merge: rule ask + model warn -> ask (rule is the floor)', () => {
  const d = mergeVerdicts(
    { action: 'ask', matchedRules: ['p1'], message: 'rule asks' },
    { action: 'warn', reason: 'model warns' },
  )
  assert.equal(d.action, 'ask')
  assert.equal(d.source, 'rule')
})

test('merge: rule warn + model ask -> ask (model is stricter)', () => {
  const d = mergeVerdicts(
    { action: 'warn', matchedRules: ['p1'], message: 'rule warns' },
    { action: 'ask', reason: 'model asks' },
  )
  assert.equal(d.action, 'ask')
  assert.equal(d.source, 'both')
})

test('merge: rule allow + model null -> allow (default)', () => {
  const d = mergeVerdicts({ action: 'allow', matchedRules: [], message: 'd' }, null)
  assert.equal(d.action, 'allow')
  assert.equal(d.source, 'rule')
})

test('merge: rule null + model block -> model block', () => {
  const d = mergeVerdicts(null, { action: 'block', reason: 'model only' })
  assert.equal(d.action, 'block')
  assert.equal(d.source, 'model')
})

test('merge: both null -> allow with default message', () => {
  const d = mergeVerdicts(null, null)
  assert.equal(d.action, 'allow')
})

// ── monitor mode: a downgraded rule verdict can never be re-escalated ──

test('merge: monitor-downgraded rule warn + model block -> stays warn (monitor never denies)', () => {
  const d = mergeVerdicts(
    { action: 'warn', matchedRules: ['p1'], message: 'rule warns', policyId: 'p1', monitorDowngraded: true },
    { action: 'block', reason: 'model says no' },
  )
  assert.equal(d.action, 'warn', 'the model stage must not undo the monitor downgrade')
  assert.equal(d.monitorDowngraded, true)
  assert.equal(d.source, 'both')
  assert.equal(d.message, 'model says no', 'the model reason still explains the warn')
  assert.equal(d.modelVerdict?.action, 'block', 'model verdict preserved for the audit trail')
})

test('merge: monitor-downgraded rule warn + model ask -> stays warn', () => {
  const d = mergeVerdicts(
    { action: 'warn', matchedRules: ['p1'], message: 'rule warns', policyId: 'p1', monitorDowngraded: true },
    { action: 'ask', reason: 'model asks' },
  )
  assert.equal(d.action, 'warn')
  assert.equal(d.monitorDowngraded, true)
})

test('merge: plain rule warn + model block -> block (protect mode upgrades freely)', () => {
  const d = mergeVerdicts(
    { action: 'warn', matchedRules: ['p1'], message: 'rule warns' },
    { action: 'block', reason: 'model says no' },
  )
  assert.equal(d.action, 'block', 'without the downgrade flag strictest-wins is unchanged')
})

// ── engine orchestration with injected fake stages ──

test('engine: model stage disabled -> rule verdict only', async () => {
  const rules = { decide: () => ({ action: 'block', matchedRules: ['p'], message: 'x' }) }
  const model = { enabled: () => false, evaluate: async () => ({ action: 'allow', reason: 'never' }) }
  const engine = new ModelReviewEngine(rules, model)
  const d = await engine.evaluate({ eventType: 'before_tool_call', data: {}, context: {} })
  assert.equal(d.action, 'block')
  assert.equal(d.source, 'rule')
})

test('engine: rule block -> model stage is NOT called (short-circuit: strictest verdict)', async () => {
  let evaluateCalls = 0
  let enabledCalls = 0
  const rules = { decide: () => ({ action: 'block', matchedRules: ['p'], message: 'x' }) }
  const model = {
    enabled: () => { enabledCalls += 1; return true },
    evaluate: async () => { evaluateCalls += 1; return { action: 'allow', reason: 'never reached' } },
  }
  const engine = new ModelReviewEngine(rules, model)
  const d = await engine.evaluate({ eventType: 'before_tool_call', data: {}, context: {} })
  assert.equal(d.action, 'block')
  assert.equal(d.source, 'rule')
  assert.equal(evaluateCalls, 0, 'model evaluate must not run')
  assert.equal(enabledCalls, 0, 'model enabled() must not even be consulted')
})

test('engine: rule ask + model block -> block (strictest wins)', async () => {
  let evaluateCalls = 0
  const rules = { decide: () => ({ action: 'ask', matchedRules: ['p'], message: 'rule asks' }) }
  const model = {
    enabled: () => true,
    evaluate: async () => { evaluateCalls += 1; return { action: 'block', reason: 'model doubles down' } },
  }
  const engine = new ModelReviewEngine(rules, model)
  const d = await engine.evaluate({ eventType: 'before_tool_call', data: {}, context: {} })
  assert.equal(evaluateCalls, 1, 'model must run when the rule is not block')
  assert.equal(d.action, 'block')
  assert.equal(d.source, 'both')
  assert.equal(d.modelVerdict?.reason, 'model doubles down')
})

test('engine: rule ask + model warn -> rule ask stands (floor)', async () => {
  const rules = { decide: () => ({ action: 'ask', matchedRules: ['p'], message: 'rule asks' }) }
  const model = {
    enabled: () => true,
    evaluate: async () => ({ action: 'warn', reason: 'looks soft' }),
  }
  const engine = new ModelReviewEngine(rules, model)
  const d = await engine.evaluate({ eventType: 'before_tool_call', data: {}, context: {} })
  assert.equal(d.action, 'ask')
  assert.equal(d.source, 'rule')
})

test('engine: rule warn + model ask -> ask (model stricter)', async () => {
  const rules = { decide: () => ({ action: 'warn', matchedRules: ['p'], message: 'rule warns' }) }
  const model = {
    enabled: () => true,
    evaluate: async () => ({ action: 'ask', reason: 'needs confirmation' }),
  }
  const engine = new ModelReviewEngine(rules, model)
  const d = await engine.evaluate({ eventType: 'before_tool_call', data: {}, context: {} })
  assert.equal(d.action, 'ask')
  assert.equal(d.source, 'both')
})

test('engine: model stage upgrades allow -> warn', async () => {
  const rules = { decide: () => ({ action: 'allow', matchedRules: [], message: 'd' }) }
  const model = {
    enabled: () => true,
    evaluate: async () => ({ action: 'warn', reason: 'suspicious' }),
  }
  const engine = new ModelReviewEngine(rules, model)
  const d = await engine.evaluate({ eventType: 'before_tool_call', data: {}, context: {} })
  assert.equal(d.action, 'warn')
  assert.equal(d.source, 'both')
  assert.equal(d.modelVerdict?.reason, 'suspicious')
})

test('engine: model error fails open to the rule verdict', async () => {
  const rules = { decide: () => ({ action: 'allow', matchedRules: [], message: 'd' }) }
  const model = {
    enabled: () => true,
    evaluate: async () => { throw new Error('boom') },
  }
  const engine = new ModelReviewEngine(rules, model)
  const d = await engine.evaluate({ eventType: 'before_tool_call', data: {}, context: {} })
  assert.equal(d.action, 'allow')
})

test('engine: rule stage disabled -> model verdict only', async () => {
  const rules = { decide: () => ({ action: 'allow', matchedRules: [], message: 'never' }), rulesEnabled: () => false }
  const model = {
    enabled: () => true,
    evaluate: async () => ({ action: 'block', reason: 'model only' }),
  }
  const engine = new ModelReviewEngine(rules, model)
  const d = await engine.evaluate({ eventType: 'before_tool_call', data: {}, context: {} })
  assert.equal(d.action, 'block')
  assert.equal(d.source, 'model')
})

test('engine: engine-level monitor mode caps the model stage at warn', async () => {
  const rules = {
    decide: () => ({ action: 'warn', matchedRules: ['p'], message: 'rule warns' }),
    defaultMode: 'monitor',
  }
  const model = { enabled: () => true, evaluate: async () => ({ action: 'block', reason: 'model says no' }) }
  const engine = new ModelReviewEngine(rules, model)
  const d = await engine.evaluate({ eventType: 'before_tool_call', data: {}, context: {} })
  assert.equal(d.action, 'warn', 'monitor mode never denies, even when the model stage escalates')
  assert.equal(d.monitorDowngraded, true)
  assert.equal(d.modelVerdict?.reason, 'model says no')
})

test('engine: rules disabled + engine monitor + model block -> capped to warn', async () => {
  const rules = {
    decide: () => { throw new Error('rule stage must not run') },
    rulesEnabled: () => false,
    defaultMode: 'monitor',
  }
  const model = { enabled: () => true, evaluate: async () => ({ action: 'block', reason: 'model only' }) }
  const engine = new ModelReviewEngine(rules, model)
  const d = await engine.evaluate({ eventType: 'before_tool_call', data: {}, context: {} })
  assert.equal(d.action, 'warn', 'engine-level monitor applies even without a rule verdict')
  assert.equal(d.monitorDowngraded, true)
  assert.equal(d.source, 'model')
})

test('engine: engine-level protect mode still lets the model escalate', async () => {
  const rules = {
    decide: () => ({ action: 'warn', matchedRules: ['p'], message: 'rule warns' }),
    defaultMode: 'protect',
  }
  const model = { enabled: () => true, evaluate: async () => ({ action: 'block', reason: 'model says no' }) }
  const engine = new ModelReviewEngine(rules, model)
  const d = await engine.evaluate({ eventType: 'before_tool_call', data: {}, context: {} })
  assert.equal(d.action, 'block', 'protect mode keeps strictest-wins')
  assert.equal(d.monitorDowngraded, undefined)
})

test('engine: both stages disabled -> allow by default', async () => {
  const rules = { decide: () => ({ action: 'block', matchedRules: ['p'], message: 'x' }), rulesEnabled: () => false }
  const model = { enabled: () => false, evaluate: async () => null }
  const engine = new ModelReviewEngine(rules, model)
  const d = await engine.evaluate({ eventType: 'before_tool_call', data: {}, context: {} })
  assert.equal(d.action, 'allow')
})

// ── DefaultModelStage with an injected fake caller/parser (no network) ──

test('stage: DefaultModelStage parses caller output and caps raw', async () => {
  const stage = new DefaultModelStage({
    config: () => ({
      enabled: true,
      mode: 'custom',
      baselineTemplates: [{ id: 'base', name: 'default', hooks: ['tools/pre-execute'], enabled: true, prompt: 'review {content}' }],
      templates: [],
      baseUrl: 'http://localhost',
      apiKey: 'k',
      model: 'm',
      timeoutMs: 1000,
    }),
    caller: () => async () => '{"action":"ask","reason":"human check needed"}',
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
  })
  const v = await stage.evaluate({
    eventType: 'before_tool_call',
    data: { toolName: 'bash' },
    context: {},
    content: 'curl x',
  })
  assert.equal(v?.action, 'ask')
  assert.ok(v?.raw?.includes('"action":"ask"'), 'raw output preserved (bounded)')
})

test('stage: caller/parser failure -> null (fail-open to rules)', async () => {
  const stage = new DefaultModelStage({
    config: () => ({ enabled: true, mode: 'custom', baselineTemplates: [{ id: 'base', name: 'default', hooks: ['tools/pre-execute'], enabled: true, prompt: 'review {content}' }], templates: [], baseUrl: 'http://localhost', apiKey: 'k', model: 'm', timeoutMs: 1000 }),
    caller: () => async () => { throw new Error('timeout') },
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
  })
  const v = await stage.evaluate({ eventType: 'before_tool_call', data: {}, context: {} })
  assert.equal(v, null)
})

// ── onReview observability seam ──

test('stage: fires onReview with provider / request body / response body on a parsed verdict', async () => {
  const records = []
  const stage = new DefaultModelStage({
    config: () => ({ enabled: true, mode: 'custom', baselineTemplates: [], templates: [{ id: 't1', name: 'T1', hooks: ['tools/pre-execute'], enabled: true, prompt: '{hookType} -- {content}' }], baseUrl: 'http://localhost:9999', apiKey: 'k', model: 'reviewer', timeoutMs: 1000 }),
    caller: () => async () => '{"action":"ask","reason":"check please"}',
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
    onReview: (record) => records.push(record),
  })
  const v = await stage.evaluate({ eventType: 'before_tool_call', sessionId: 's1', data: { toolName: 'bash' }, context: {}, content: 'curl x' })
  assert.equal(v?.action, 'ask')
  assert.equal(records.length, 1)
  const rec = records[0]
  assert.equal(rec.status, 'ok')
  assert.equal(rec.action, 'ask')
  assert.equal(rec.reason, 'check please')
  assert.equal(rec.sessionId, 's1')
  assert.equal(rec.hook, 'before_tool_call')
  assert.equal(rec.tool, 'bash')
  assert.deepEqual(rec.provider, { mode: 'custom', baseUrl: 'http://localhost:9999', model: 'reviewer' })
  assert.ok(rec.request?.includes('before_tool_call'), 'request carries the rendered review prompt')
  assert.ok(rec.request?.includes('curl x'), 'request carries the reviewed content')
  assert.ok(rec.response?.includes('"action":"ask"'), 'response carries the raw model output')
  assert.equal(typeof rec.durationMs, 'number')
})

test('stage: a custom template disposition cap clamps a stricter model verdict', async () => {
  const records = []
  const stage = new DefaultModelStage({
    config: () => ({ enabled: true, mode: 'custom', baselineTemplates: [], templates: [{ id: 't1', name: 'T1', hooks: ['tools/pre-execute'], enabled: true, prompt: '{content}', action: 'ask' }], baseUrl: 'http://localhost:9999', apiKey: 'k', model: 'reviewer', timeoutMs: 1000 }),
    caller: () => async () => '{"action":"block","reason":"dangerous"}',
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
    onReview: (record) => records.push(record),
  })
  const v = await stage.evaluate({ eventType: 'before_tool_call', sessionId: 's1', data: { toolName: 'bash' }, context: {}, content: 'curl x' })
  assert.equal(v?.action, 'ask', 'a block verdict clamps down to the configured ask cap')
  assert.equal(v?.reason, 'dangerous', 'the parsed reason survives the clamp')
  assert.equal(records[0]?.action, 'ask', 'the audit row records the delivered (clamped) action')
})

test('stage: allow/warn caps clamp; absent or unknown cap keeps the verdict uncapped', async () => {
  const build = (action) => new DefaultModelStage({
    config: () => ({ enabled: true, mode: 'custom', baselineTemplates: [], templates: [{ id: 't1', name: 'T1', hooks: ['tools/pre-execute'], enabled: true, prompt: '{content}', ...(action === undefined ? {} : { action }) }], baseUrl: 'http://localhost:9999', apiKey: 'k', model: 'reviewer', timeoutMs: 1000 }),
    caller: () => async () => '{"action":"block","reason":"r"}',
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
  })
  assert.equal((await build('allow').evaluate({ eventType: 'before_tool_call', data: {}, context: {} }))?.action, 'allow',
    'allow cap = audit-only: even a block verdict delivers allow')
  assert.equal((await build('warn').evaluate({ eventType: 'before_tool_call', data: {}, context: {} }))?.action, 'warn',
    'warn cap clamps block down to warn')
  assert.equal((await build(undefined).evaluate({ eventType: 'before_tool_call', data: {}, context: {} }))?.action, 'block',
    'absent cap = uncapped')
  assert.equal((await build('execute-everything').evaluate({ eventType: 'before_tool_call', data: {}, context: {} }))?.action, 'block',
    'an unknown cap value falls back to uncapped (fail-safe)')
})

test('stage: fires onReview error records for caller failures and unparseable output', async () => {
  const records = []
  const failing = new DefaultModelStage({
    config: () => ({ enabled: true, mode: 'session', baselineTemplates: [{ id: 'base', name: 'default', hooks: ['tools/pre-execute'], enabled: true, prompt: 'review {content}' }], templates: [], baseUrl: '', apiKey: '', model: '', timeoutMs: 1000 }),
    caller: () => async () => { throw new Error('timeout') },
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
    sessionRoute: () => ({ provider: 'deepseek', model: 'deepseek-chat' }),
    onReview: (record) => records.push(record),
  })
  const v = await failing.evaluate({ eventType: 'before_tool_call', sessionId: 's1', data: {}, context: {} })
  assert.equal(v, null)
  assert.equal(records.length, 1)
  assert.equal(records[0].status, 'error')
  assert.equal(records[0].error, 'timeout')
  assert.deepEqual(records[0].provider, { mode: 'session', provider: 'deepseek', model: 'deepseek-chat' })

  const records2 = []
  const misparse = new DefaultModelStage({
    config: () => ({ enabled: true, mode: 'session', baselineTemplates: [{ id: 'base', name: 'default', hooks: ['tools/pre-execute'], enabled: true, prompt: 'review {content}' }], templates: [], baseUrl: '', apiKey: '', model: '', timeoutMs: 1000 }),
    caller: () => async () => 'not json at all',
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
    sessionRoute: () => ({ provider: 'deepseek', model: 'deepseek-chat' }),
    onReview: (record) => records2.push(record),
  })
  const v2 = await misparse.evaluate({ eventType: 'before_tool_call', sessionId: 's1', data: {}, context: {} })
  assert.equal(v2, null)
  assert.equal(records2.length, 1)
  assert.equal(records2[0].status, 'error')
  assert.equal(records2[0].error, 'model output not parseable')
  assert.equal(records2[0].response, 'not json at all', 'response body kept for post-mortem')
  assert.equal(typeof records2[0].durationMs, 'number')
})

// ── end-to-end: the built-in prompt's output shape drives the final verdict ──

test('pipeline: a rule-allow event is blocked by the model audit verdict (shipped wiring)', async () => {
  const auditOutput = 'I will analyse both dimensions.\n'
    + '```json\n{"user_request_risks":["No Risk"],"user_request_reason":"",'
    + '"agent_behavior_risks":["Destructive Command"],'
    + '"agent_behavior_reason":"agent issued rm -rf /var/lib"}\n```'
  const stage = new DefaultModelStage({
    config: () => ({
      enabled: true,
      mode: 'custom',
      baselineTemplates: [{ id: 'base', name: 'default', hooks: ['tools/pre-execute'], enabled: true, prompt: 'audit {content}' }],
      templates: [],
      baseUrl: 'http://localhost',
      apiKey: 'k',
      model: 'm',
      timeoutMs: 1000,
    }),
    caller: () => async () => auditOutput,
    parser: createModelVerdictParser(),
    truncate: (text) => text,
  })
  const engine = new ModelReviewEngine(
    { decide: () => ({ action: 'allow', matchedRules: [], message: 'no policy matched' }) },
    stage,
  )
  const decision = await engine.evaluate({
    eventType: 'before_tool_call',
    data: { toolName: 'bash' },
    context: {},
    content: 'rm -rf /var/lib',
  })
  // Before the audit parser landed, this exact response was "model output not
  // parseable" and the decision stayed `allow` on the rule verdict.
  assert.equal(decision.action, 'block')
  assert.equal(decision.source, 'both')
  assert.ok(decision.message.includes('Destructive Command'), 'the matched category reaches the audit row')
  assert.equal(decision.modelVerdict?.action, 'block')
})

test('pipeline: a clean audit verdict leaves a rule allow untouched', async () => {
  const stage = new DefaultModelStage({
    config: () => ({
      enabled: true,
      mode: 'custom',
      baselineTemplates: [{ id: 'base', name: 'default', hooks: ['tools/pre-execute'], enabled: true, prompt: 'audit {content}' }],
      templates: [],
      baseUrl: 'http://localhost',
      apiKey: 'k',
      model: 'm',
      timeoutMs: 1000,
    }),
    caller: () => async () => '{"user_request_risks":["No Risk"],"user_request_reason":"",'
      + '"agent_behavior_risks":["No Risk"],"agent_behavior_reason":""}',
    parser: createModelVerdictParser(),
    truncate: (text) => text,
  })
  const engine = new ModelReviewEngine(
    { decide: () => ({ action: 'allow', matchedRules: [], message: 'no policy matched' }) },
    stage,
  )
  const decision = await engine.evaluate({
    eventType: 'before_tool_call', data: { toolName: 'bash' }, context: {}, content: 'ls',
  })
  assert.equal(decision.action, 'allow')
  assert.equal(decision.source, 'rule', 'a model allow never overrides the rule verdict')
})

// ── session-mode first-request race: skip + post-hoc make-up ──────────────

/** Session-mode config factory; `makeupReview` overrides the (off) default. */
function sessionConfig(overrides = {}) {
  return { enabled: true, mode: 'session', makeupReview: false, baselineTemplates: [{ id: 'base', name: 'default', hooks: ['tools/pre-execute'], enabled: true, prompt: 'review {content}' }], templates: [], baseUrl: '', apiKey: '', model: '', timeoutMs: 1000, ...overrides }
}

test('stage: session mode without a resolvable route skips silently and parks the event', async () => {
  const records = []
  const stage = new DefaultModelStage({
    config: () => sessionConfig({ makeupReview: true }),
    // The caller would throw if reached; the stage must skip BEFORE calling it.
    caller: () => async () => { throw new Error('must not be called') },
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
    sessionRoute: () => undefined,
    onReview: (record) => records.push(record),
  })
  const v = await stage.evaluate({ eventType: 'before_tool_call', sessionId: 's1', data: { toolName: 'bash', callId: 'c1' }, context: {}, content: 'ls' })
  assert.equal(v, null, 'fail-open: no verdict from a skipped attempt')
  assert.equal(records.length, 1)
  const rec = records[0]
  assert.equal(rec.status, 'skipped')
  assert.equal(rec.sessionId, 's1')
  assert.equal(rec.tool, 'bash')
  assert.equal(rec.callId, 'c1')
  assert.ok(typeof rec.note === 'string' && rec.note.includes('make-up'), 'skip note explains the timing race')
  assert.equal(rec.late, undefined)
})

test('stage: parked events get one post-hoc make-up review flagged late (audit-only)', async () => {
  const records = []
  let routeReady = false
  const calls = []
  const stage = new DefaultModelStage({
    config: () => sessionConfig({ makeupReview: true }),
    caller: () => async () => {
      calls.push(calls.length + 1)
      return '{"action":"warn","reason":"post-hoc look"}'
    },
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
    sessionRoute: () => (routeReady ? { provider: 'deepseek', model: 'deepseek-chat' } : undefined),
    onReview: (record) => records.push(record),
  })

  // First event: no route yet → skipped record only, verdict null.
  const first = await stage.evaluate({ eventType: 'before_tool_call', sessionId: 's1', data: { toolName: 'bash' }, context: {}, content: 'first' })
  assert.equal(first, null)
  assert.equal(records.length, 1)
  assert.equal(records[0].status, 'skipped')
  assert.equal(calls.length, 0, 'no model call while the route is missing')

  // Second event: route became ready → its own live review runs…
  routeReady = true
  const second = await stage.evaluate({ eventType: 'before_tool_call', sessionId: 's2', data: {}, context: {}, content: 'second' })
  assert.equal(second?.action, 'warn')
  // …and the drain flushes the parked make-up asynchronously.
  await new Promise((resolve) => setTimeout(resolve, 0))
  const late = records.filter((r) => r.status !== 'skipped' && r.late === true)
  assert.equal(late.length, 1, 'exactly one make-up row for the parked event')
  assert.equal(late[0].sessionId, 's1', 'the make-up reviews the originally skipped event')
  assert.ok(late[0].note.includes('audit-only'), 'make-up rows carry the non-enforcing annotation')
  assert.deepEqual(late[0].provider, { mode: 'session', provider: 'deepseek', model: 'deepseek-chat' },
    'make-up names the model that actually served it')
  assert.equal(calls.length, 2, 'one live + one make-up call')
})

test('stage: custom mode never skips — missing route is not consulted', async () => {
  const records = []
  const stage = new DefaultModelStage({
    config: () => ({ enabled: true, mode: 'custom', baselineTemplates: [{ id: 'base', name: 'default', hooks: ['tools/pre-execute'], enabled: true, prompt: 'review {content}' }], templates: [], baseUrl: 'http://localhost:9999', apiKey: 'k', model: 'reviewer', timeoutMs: 1000 }),
    caller: () => async () => '{"action":"allow","reason":"fine"}',
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
    sessionRoute: () => undefined,
    onReview: (record) => records.push(record),
  })
  const v = await stage.evaluate({ eventType: 'before_tool_call', sessionId: 's1', data: {}, context: {}, content: 'x' })
  assert.equal(v?.action, 'allow')
  assert.equal(records[0].status, 'ok')
})

test('stage: with the makeup switch off (default) skipped events are never queued nor reviewed', async () => {
  const records = []
  const calls = []
  const stage = new DefaultModelStage({
    // No makeupReview key at all — legacy persisted prefs behave as off.
    config: () => ({ enabled: true, mode: 'session', baselineTemplates: [{ id: 'base', name: 'default', hooks: ['tools/pre-execute'], enabled: true, prompt: 'review {content}' }], templates: [], baseUrl: '', apiKey: '', model: '', timeoutMs: 1000 }),
    caller: () => async () => { calls.push(1); return '{"action":"allow","reason":"fine"}' },
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
    sessionRoute: () => undefined,
    onReview: (record) => records.push(record),
  })
  const first = await stage.evaluate({ eventType: 'before_tool_call', sessionId: 's1', data: { toolName: 'bash' }, context: {}, content: 'first' })
  assert.equal(first, null)
  assert.equal(records[0].status, 'skipped', 'skip still observable')
  assert.equal(calls.length, 0)

  // No second-event path can drain anything (nothing was queued): even after a
  // ready-route evaluation the parked event is gone — it never entered a queue.
  const recsBefore = records.length
  await new Promise((resolve) => setTimeout(resolve, 0))
  assert.equal(records.length, recsBefore, 'no late make-up rows when the switch is off')
})

// ── per-hook review-template chain (baseline cards + custom templates) ──

/** One baseline template card bound to the hook under test. */
const baseCard = 'baseline {content}'

test('stage: the template chain aggregates strictest-wins and prefixes template names', async () => {
  const calls = []
  const records = []
  const responses = ['{"action":"warn","reason":"w1"}', '{"action":"ask","reason":"a1"}', '{"action":"allow","reason":"ok"}']
  const stage = new DefaultModelStage({
    config: () => ({
      enabled: true, mode: 'custom',
      baselineTemplates: [{ id: 'base', name: 'default', hooks: ['tools/pre-execute'], enabled: true, prompt: baseCard }],
      templates: [
        { id: 't1', name: 'T1', hook: 'before_tool_call', enabled: true, prompt: 't1 {content}' },
        { id: 't2', name: 'T2', hook: 'before_tool_call', enabled: true, prompt: 't2 {content}' },
      ],
      baseUrl: 'http://localhost', apiKey: 'k', model: 'm', timeoutMs: 1000,
    }),
    // The engine invokes the fake as `callerFn.call(spec)`, so the request
    // spec arrives as `this` (not an argument) — hence the plain functions.
    caller: () => function () { calls.push(this.prompt); return Promise.resolve(responses[calls.length - 1] ?? '{"action":"allow","reason":"ok"}') },
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
    onReview: (record) => records.push(record),
  })
  const v = await stage.evaluate({ eventType: 'before_tool_call', data: {}, context: {}, content: 'x' })
  // Chain = baseline + T1 + T2, in order; strictest of (warn, ask, allow) = ask.
  assert.equal(calls.length, 3, 'every chain template is called')
  assert.ok(calls[0].startsWith('baseline '), 'the baseline template runs first')
  assert.ok(calls[1].startsWith('t1 '), 'custom templates follow in array order')
  assert.equal(v?.action, 'ask')
  assert.equal(v?.reason, '[T1] a1', 'the strictest verdict carries the template-name prefix')
  assert.equal(records.length, 3)
  assert.equal(records[0].template, 'default')
  assert.equal(records[1].template, 'T1')
  assert.equal(records[2].template, 'T2')
})

test('stage: a block verdict short-circuits the chain (later templates not called)', async () => {
  const calls = []
  const stage = new DefaultModelStage({
    config: () => ({
      enabled: true, mode: 'custom',
      baselineTemplates: [{ id: 'base', name: 'default', hooks: ['tools/pre-execute'], enabled: true, prompt: baseCard }],
      templates: [{ id: 't1', name: 'T1', hook: 'before_tool_call', enabled: true, prompt: 't1 {content}' }],
      baseUrl: 'http://localhost', apiKey: 'k', model: 'm', timeoutMs: 1000,
    }),
    caller: () => function () { calls.push(this.prompt); return Promise.resolve('{"action":"block","reason":"b1"}') },
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
  })
  const v = await stage.evaluate({ eventType: 'before_tool_call', data: {}, context: {}, content: 'x' })
  assert.equal(v?.action, 'block')
  assert.equal(v?.reason, '[default] b1', 'the short-circuiting block carries its template name')
  assert.equal(calls.length, 1, 'later templates never run after a block')
})

test('stage: disabled templates and other-hook templates are skipped; baseline cards + no customs → no review', async () => {
  const calls = []
  const mk = (templates, baseEnabled) => new DefaultModelStage({
    config: () => ({
      enabled: true, mode: 'custom',
      baselineTemplates: [{ id: 'base', name: 'default', hooks: ['tools/pre-execute'], enabled: baseEnabled, prompt: baseCard }],
      templates,
      baseUrl: 'http://localhost', apiKey: 'k', model: 'm', timeoutMs: 1000,
    }),
    caller: () => function () { calls.push(this.prompt); return Promise.resolve('{"action":"warn","reason":"w"}') },
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
  })
  // A disabled template and a template bound to another hook are both skipped:
  // with the baseline card off, that hook stays silent.
  const stage = mk([
    { id: 'off', name: 'Off', hook: 'before_tool_call', enabled: false, prompt: 'off' },
    { id: 'other', name: 'Other', hook: 'before_prompt_build', enabled: true, prompt: 'other' },
  ], false)
  const v = await stage.evaluate({ eventType: 'before_tool_call', data: {}, context: {}, content: 'x' })
  assert.equal(calls.length, 0, 'a disabled baseline card + no enabled customs for the hook → empty chain')
  assert.equal(v, null)
  // Baseline card on → runs as the sole enabled chain entry.
  const single = mk([], true)
  const v1 = await single.evaluate({ eventType: 'before_tool_call', data: {}, context: {}, content: 'x' })
  assert.equal(calls.length, 1)
  assert.ok(calls[0].startsWith('baseline '))
  assert.equal(v1?.action, 'warn')
  assert.equal(v1?.reason, 'w', 'a single-template chain keeps the bare reason (no prefix)')
})

test('stage: a failing template does not abort the chain (fail-open per template)', async () => {
  const calls = []
  const records = []
  let n = 0
  const stage = new DefaultModelStage({
    config: () => ({
      enabled: true, mode: 'custom',
      baselineTemplates: [{ id: 'base', name: 'default', hooks: ['tools/pre-execute'], enabled: true, prompt: baseCard }],
      templates: [{ id: 't1', name: 'T1', hook: 'before_tool_call', enabled: true, prompt: 't1 {content}' }],
      baseUrl: 'http://localhost', apiKey: 'k', model: 'm', timeoutMs: 1000,
    }),
    caller: () => function () {
      calls.push(this.prompt)
      n += 1
      if (n === 1) return Promise.reject(new Error('boom'))
      return Promise.resolve('{"action":"warn","reason":"w2"}')
    },
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
    onReview: (record) => records.push(record),
  })
  const v = await stage.evaluate({ eventType: 'before_tool_call', data: {}, context: {}, content: 'x' })
  assert.equal(calls.length, 2, 'the chain continues after a template failure')
  assert.equal(v?.action, 'warn')
  assert.equal(v?.reason, '[T1] w2')
  assert.equal(records[0].status, 'error')
  assert.equal(records[1].status, 'ok')
})

test('stage: all templates fail → null (rule verdict stands)', async () => {
  const stage = new DefaultModelStage({
    config: () => ({
      enabled: true, mode: 'custom',
      baselineTemplates: [{ id: 'base', name: 'default', hooks: ['tools/pre-execute'], enabled: true, prompt: baseCard }],
      templates: [{ id: 't1', name: 'T1', hook: 'before_tool_call', enabled: true, prompt: 't1' }],
      baseUrl: 'http://localhost', apiKey: 'k', model: 'm', timeoutMs: 1000,
    }),
    caller: () => async () => { throw new Error('down') },
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
  })
  const v = await stage.evaluate({ eventType: 'before_tool_call', data: {}, context: {}, content: 'x' })
  assert.equal(v, null)
})

test('stage: a blank baseline prompt is skipped (also with custom templates absent)', async () => {
  const calls = []
  const stage = new DefaultModelStage({
    config: () => ({
      enabled: true, mode: 'custom',
      baselineTemplates: [{ id: 'base', name: 'default', hooks: ['tools/pre-execute'], enabled: true, prompt: '   ' }],
      templates: [{ id: 't1', name: 'T1', hook: 'before_tool_call', enabled: true, prompt: 't1 {content}' }],
      baseUrl: 'http://localhost', apiKey: 'k', model: 'm', timeoutMs: 1000,
    }),
    caller: () => function () { calls.push(this.prompt); return Promise.resolve('{"action":"allow","reason":"ok"}') },
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
  })
  const v = await stage.evaluate({ eventType: 'before_tool_call', data: {}, context: {}, content: 'x' })
  assert.equal(calls.length, 1, 'the blank baseline card is skipped; the custom template still runs')
  assert.ok(calls[0].startsWith('t1 '))
  assert.equal(v?.action, 'allow')
})

test('stage: a baseline card bound to another hook stays silent; enabled gates it per card', async () => {
  const calls = []
  const stage = new DefaultModelStage({
    config: () => ({
      enabled: true, mode: 'custom',
      baselineTemplates: [
        { id: 'base', name: 'default', hooks: ['tools/pre-execute'], enabled: true, prompt: baseCard },
        { id: 'off', name: 'Off', hooks: ['tools/pre-execute'], enabled: false, prompt: 'off {content}' },
        { id: 'other', name: 'Other', hooks: ['agent/pre-step'], enabled: true, prompt: 'other {content}' },
      ],
      templates: [],
      baseUrl: 'http://localhost', apiKey: 'k', model: 'm', timeoutMs: 1000,
    }),
    caller: () => function () { calls.push(this.prompt); return Promise.resolve('{"action":"warn","reason":"w"}') },
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
  })
  // The bound-to-another-hook card and the disabled card are skipped: only the
  // enabled tools/pre-execute card runs.
  const v = await stage.evaluate({ eventType: 'before_tool_call', data: {}, context: {}, content: 'x' })
  assert.equal(calls.length, 1)
  assert.ok(calls[0].startsWith('baseline '))
  assert.equal(v?.action, 'warn')
})

test('stage: multiple baseline cards on the same hook run in shipped order before customs', async () => {
  const calls = []
  const stage = new DefaultModelStage({
    config: () => ({
      enabled: true, mode: 'custom',
      baselineTemplates: [
        { id: 'risk', name: 'Risk', hooks: ['tools/pre-execute'], enabled: true, prompt: 'risk {content}' },
        { id: 'drift', name: 'Drift', hooks: ['tools/pre-execute'], enabled: true, prompt: 'drift {content}' },
      ],
      templates: [{ id: 't1', name: 'T1', hook: 'before_tool_call', enabled: true, prompt: 't1 {content}' }],
      baseUrl: 'http://localhost', apiKey: 'k', model: 'm', timeoutMs: 1000,
    }),
    caller: () => function () { calls.push(this.prompt); return Promise.resolve('{"action":"allow","reason":"ok"}') },
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
  })
  const v = await stage.evaluate({ eventType: 'before_tool_call', data: {}, context: {}, content: 'x' })
  assert.equal(calls.length, 3, 'both baseline cards + the custom template run')
  assert.ok(calls[0].startsWith('risk '), 'baseline order preserved')
  assert.ok(calls[1].startsWith('drift '), 'baseline order preserved')
  assert.ok(calls[2].startsWith('t1 '), 'custom template follows the baseline cards')
  assert.equal(v?.action, 'allow')
})

test('stage: multi-hook templates join every listed chain (native seam names)', async () => {
  const calls = []
  const stage = new DefaultModelStage({
    config: () => ({
      enabled: true, mode: 'custom',
      baselineTemplates: [],
      // Multi-select binding: one template, two chains. The observe-only
      // lifecycle seam is also bindable (the full pipeline is registered
      // there; the verdict stays audit-only).
      templates: [{ id: 't1', name: 'T1', hooks: ['tools/pre-execute', 'agent/pre-step', 'subagent/end'], enabled: true, prompt: 't1 {content}' }],
      baseUrl: 'http://localhost', apiKey: 'k', model: 'm', timeoutMs: 1000,
    }),
    caller: () => function () { calls.push(this.prompt); return Promise.resolve('{"action":"allow","reason":"ok"}') },
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
  })
  await stage.evaluate({ eventType: 'tools/pre-execute', data: {}, context: {}, content: 'x' })
  await stage.evaluate({ eventType: 'agent/pre-step', data: {}, context: {}, content: 'y' })
  await stage.evaluate({ eventType: 'subagent/end', data: {}, context: {}, content: 'w' })
  await stage.evaluate({ eventType: 'tools/post-execute', data: {}, context: {}, content: 'z' })
  assert.deepEqual(calls, ['t1 x', 't1 y', 't1 w'],
    'the template runs on every bound hook (incl. the observe-only seam) and nowhere else')
})

test('stage: legacy single `hook` keeps loading; a present `hooks` array wins', async () => {
  const mk = (templates) => new DefaultModelStage({
    config: () => ({
      enabled: true, mode: 'custom',
      baselineTemplates: [],
      templates,
      baseUrl: 'http://localhost', apiKey: 'k', model: 'm', timeoutMs: 1000,
    }),
    caller: () => function () { mkCalls.push(this.prompt); return Promise.resolve('{"action":"allow","reason":"ok"}') },
    parser: new JsonModelVerdictParser(),
    truncate: (text) => text,
  })
  const mkCalls = []
  // v0.1.x archive: single legacy `hook`, canonicalized against native events.
  await mk([{ id: 't1', name: 'T1', hook: 'before_tool_call', enabled: true, prompt: 't1 {content}' }])
    .evaluate({ eventType: 'tools/pre-execute', data: {}, context: {}, content: 'x' })
  assert.deepEqual(mkCalls, ['t1 x'], 'legacy single hook still binds (canonicalized to the native seam)')
  // Precedence: when `hooks` is present it wins over the deprecated field —
  // an empty array means the template runs nowhere.
  mkCalls.length = 0
  await mk([{ id: 't2', name: 'T2', hooks: [], hook: 'before_tool_call', enabled: true, prompt: 't2 {content}' }])
    .evaluate({ eventType: 'tools/pre-execute', data: {}, context: {}, content: 'x' })
  assert.deepEqual(mkCalls, [], 'an explicit empty `hooks` array disables the template (array form wins)')
})

// ── two-line audit prompts (Malicious Intent Detection / Risky Instruction Detection / Intent Drift Detection) ──

test('audit prompts: the three baseline templates render their placeholders', () => {
  for (const prompt of [USER_REQUEST_RISK_PROMPT, AGENT_BEHAVIOR_RISK_PROMPT, INTENT_DRIFT_PROMPT]) {
    assert.ok(prompt.includes('{user_query}'), 'every baseline audit prompt carries {user_query}')
    assert.ok(!prompt.includes('{{'), 'no doubled-brace escape reaches the model')
    assert.ok(!prompt.includes('}}'), 'no doubled-brace escape reaches the model')
  }
  assert.ok(AGENT_BEHAVIOR_RISK_PROMPT.includes('{agent_behavior}'))
  assert.ok(INTENT_DRIFT_PROMPT.includes('{agent_behavior}'))
  assert.ok(!USER_REQUEST_RISK_PROMPT.includes('{agent_behavior}'), 'Malicious Intent Detection analyzes only the user request')
})

test('audit prompts: baseline templates mount only agent/pre-step + tools/pre-execute', () => {
  assert.equal(BASELINE_REVIEW_TEMPLATES.length, 3)
  const mounts = BASELINE_REVIEW_TEMPLATES.map((t) => ({ id: t.id, name: t.name, hooks: t.hooks.slice() }))
  assert.deepEqual(mounts, [
    { id: 'malicious-intent-detection', name: '恶意意图检测', hooks: ['agent/pre-step'] },
    { id: 'risk-instruction-detection', name: '风险指令检测', hooks: ['tools/pre-execute'] },
    { id: 'intent-drift-detection', name: '意图偏离检测', hooks: ['tools/pre-execute'] },
  ])
})

test('config: the default baseline is the three audit templates, custom list empty', () => {
  assert.deepEqual(MODEL_REVIEW_DEFAULTS.baselineTemplates.map((t) => t.id), [
    'malicious-intent-detection',
    'risk-instruction-detection',
    'intent-drift-detection',
  ])
  assert.deepEqual(MODEL_REVIEW_DEFAULTS.templates, [],
    'a fresh install ships no custom templates — the baseline cards are the default review surface')
  // The settings schema seeds the same defaults (fresh install shows them).
  const resolved = GuardPrefs({}).modelReview
  assert.deepEqual(resolved.baselineTemplates.map((t) => t.id), [
    'malicious-intent-detection',
    'risk-instruction-detection',
    'intent-drift-detection',
  ])
  assert.deepEqual(resolved.templates, [])
})

// ── LineRiskModelVerdictParser: the two-line output of the three audit prompts ──

const line = (raw) => new LineRiskModelVerdictParser().parse(raw)

test('line parser: an agent-behavior destructive command -> block, reason carried', () => {
  const v = line('Destructive Command\nThe agent issued rm -rf /var/lib')
  assert.equal(v?.action, 'block')
  assert.ok(v?.reason?.includes('Destructive Command'))
  assert.ok(v?.reason?.includes('rm -rf /var/lib'))
})

test('line parser: intent drift -> ask, no drift -> allow', () => {
  const drift = line('Intent Drift\nThe tool call escalates a query into a delete')
  assert.equal(drift?.action, 'ask')
  assert.ok(drift?.reason?.includes('Intent Drift'))
  const ok = line('No Drift')
  assert.equal(ok?.action, 'allow')
  assert.equal(ok?.reason, '')
})

test('line parser: malicious intent (user request) jailbreak -> block; advisory probe -> warn', () => {
  assert.equal(line('Instruction Override / Jailbreak Inducement\nasks to ignore system instructions')?.action, 'block')
  assert.equal(line('Conversation / Context Probing\ntries to read the system prompt')?.action, 'warn')
  assert.equal(line('No Risk')?.action, 'allow')
})

test('line parser: reasoning narration before the verdict still resolves to the last category', () => {
  const v = line('Let me analyze this carefully.\nThe user seems fine.\nDestructive Command\nThe agent ran rm -rf /')
  assert.equal(v?.action, 'block')
  assert.ok(v?.reason?.includes('rm -rf /'))
})

test('line parser: a markdown-fenced verdict parses', () => {
  const v = line('```\nNo Drift\n```')
  assert.equal(v?.action, 'allow')
})

test('line parser: an unknown category degrades to warn with its verbatim name', () => {
  const v = line('Quantum Sabotage\nsome reason')
  assert.equal(v?.action, 'warn')
  assert.ok(v?.reason?.includes('Quantum Sabotage'))
})

test('line parser: garbage with no category line -> null (fail open to rules)', () => {
  assert.equal(line(''), null)
  assert.equal(line('not a verdict at all'), null)
  assert.equal(line('   '), null)
  assert.equal(line(undefined), null)
})

test('line parser: category matching tolerates case and padding drift', () => {
  assert.equal(line('  destructive   COMMAND. \n evidence here')?.action, 'block')
  assert.equal(line('  intent   drift ')?.action, 'ask')
})

// ── CompositeModelVerdictParser: JSON audit + two-line audit, both shipped shapes ──

test('composite parser: the shipped factory understands the JSON audit and the two-line shapes', () => {
  const parser = createModelVerdictParser()
  const jsonVerdict = parser.parse('{"user_request_risks":["No Risk"],"user_request_reason":"",'
    + '"agent_behavior_risks":["Destructive Command"],"agent_behavior_reason":"rm -rf /"}')
  assert.equal(jsonVerdict?.action, 'block', 'JSON audit shape keeps working')
  const lineVerdict = parser.parse('Intent Drift\nthe call exceeds the user request')
  assert.equal(lineVerdict?.action, 'ask', 'two-line audit shape parses through the same pipeline')
  const legacy = parser.parse('{"action":"warn","reason":"legacy custom template"}')
  assert.equal(legacy?.action, 'warn', 'legacy {action,reason} keeps working')
  assert.equal(parser.parse('not parseable at all'), null)
})

test('composite parser: JSON audit takes precedence over line parsing for the same output', () => {
  // The two shapes are mutually exclusive; a JSON verdict is never re-read as
  // a line category (a `{` line matches no category anyway).
  const parser = new CompositeModelVerdictParser()
  assert.equal(parser.parse('{"action":"allow","reason":"ok"}')?.action, 'allow')
  assert.equal(parser.parse('Destructive Command\nrm -rf')?.action, 'block')
})
