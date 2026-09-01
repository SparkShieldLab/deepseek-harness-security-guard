// node:test suite for the prompt-block notice: when `agent/pre-step` rejects a
// step (before_prompt_build block/ask), the adapter appends a localized
// `notice` user-message to the session so the conversation shows the user why
// their request was swallowed — instead of the message silently disappearing.
//
// Runs against lib/ after `npm run build` (build.sh compiles src -> lib).
// Usage: npm run build && node --test tools/
import test from 'node:test'
import assert from 'node:assert/strict'
import { Context } from '@deepseek-ai/cordis'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { Session, SessionId } from '@deepseek-ai/dsh-session'
import { GuardEngine } from '../lib/engine.js'
import { registerListeners } from '../lib/adapter.js'
import { GuardStateStore } from '../lib/state-store.js'

/** One blocking policy: any prompt whose text contains "rm -rf" is rejected. */
function blockingPolicy() {
  return [{
    id: 'test-block-prompt',
    hooks: ['before_prompt_build'],
    enabled: true,
    priority: 100,
    rules: [{ id: 'r1', field: 'content', operator: 'contains', value: 'rm -rf' }],
    action: 'block',
    message: '高危命令测试原因',
  }]
}

/** One ask policy on the prompt hook (no approval seam -> degrades to reject). */
function askPolicy() {
  return [{
    id: 'test-ask-prompt',
    hooks: ['before_prompt_build'],
    enabled: true,
    priority: 100,
    rules: [{ id: 'r1', field: 'content', operator: 'contains', value: 'rm -rf' }],
    action: 'ask',
    message: '需要审批测试原因',
  }]
}

/** One allow policy: proves the allow path appends nothing. */
function allowPolicy() {
  return [{
    id: 'test-allow-prompt',
    hooks: ['before_prompt_build'],
    enabled: true,
    priority: 100,
    rules: [{ id: 'r1', field: 'content', operator: 'contains', value: 'rm -rf' }],
    action: 'allow',
    message: '放行',
  }]
}

/** A session bound to a fake agent handle, mirroring the harness `Agent` face. */
function makeAgent() {
  const session = Session.create(SessionId('notice-test-session'))
  return { id: 'notice-test-session', session }
}

/** Dispatch one `agent/pre-step` waterfall through a context with the guard wired. */
async function runPreStep(policies, payload, options = {}) {
  const ctx = new Context()
  const engine = new GuardEngine(policies)
  const hooks = { beforePromptBuild: true, beforeToolCall: false, toolResultPersist: false, afterToolCall: false, systemPromptAssemble: false }
  registerListeners(ctx, engine, hooks, {
    state: new GuardStateStore(),
    lang: () => options.lang ?? 'zh',
    promptBlockNotice: options.promptBlockNotice,
  })
  const decision = await ctx.waterfall(payload.agent, 'agent/pre-step', payload, async () => ({ kind: 'enter', messages: [] }))
  return { decision, session: payload.agent.session }
}

/** The standard rejected-step payload: one user message with the banned text. */
function blockedPayload(agent, text = 'please rm -rf /tmp/x for me') {
  return {
    agent,
    messages: [createUserMessage({ content: [{ type: 'text', text }], source: { kind: 'user' } })],
    turn: 1,
    step: 1,
    signal: new AbortController().signal,
  }
}

test('block: reject AND append a notice user/message to the session', async () => {
  const agent = makeAgent()
  const { decision, session } = await runPreStep(blockingPolicy(), blockedPayload(agent))
  assert.deepEqual(decision, { kind: 'reject' })

  const notices = session.events.filter((e) => e.type === 'user/message')
  assert.equal(notices.length, 1, 'exactly one user/message appended by the guard')
  const event = notices[0]
  const source = event.data.source
  assert.equal(source.kind, 'plugin')
  assert.equal(source.plugin, 'agent-security-guard')
  assert.equal(source.form, 'notice')
  assert.equal(source.summary, '安全守卫已拦截该消息')

  // The notice lands on the model-visible surface (a plain append, no inbox claim).
  assert.ok(session.surface.nodes.includes(event.seq), 'notice seq is on the surface')

  // Body is the localized reason — and NEVER echoes the blocked content.
  const body = event.data.content[0].text
  assert.ok(body.includes('你的消息已被安全守卫拦截，未发送给模型。'), 'zh body prefix')
  assert.ok(body.includes('[test-block-prompt] 高危命令测试原因'), 'policy reason in body')
  assert.ok(!body.includes('rm -rf'), 'blocked content is never echoed back')
})

test('ask on the prompt hook degrades to reject and still appends the notice', async () => {
  const agent = makeAgent()
  const { decision, session } = await runPreStep(askPolicy(), blockedPayload(agent))
  assert.deepEqual(decision, { kind: 'reject' })
  const notice = session.events.find((e) => e.type === 'user/message')
  assert.ok(notice, 'notice appended on ask-degraded reject')
  assert.ok(notice.data.content[0].text.includes('需要审批测试原因'))
})

test('promptBlockNotice: false keeps the reject silent (no user/message appended)', async () => {
  const agent = makeAgent()
  const { decision, session } = await runPreStep(blockingPolicy(), blockedPayload(agent), { promptBlockNotice: false })
  assert.deepEqual(decision, { kind: 'reject' })
  assert.equal(session.events.filter((e) => e.type === 'user/message').length, 0)
})

test('allow: decision delegates and appends no notice', async () => {
  const agent = makeAgent()
  const { decision, session } = await runPreStep(allowPolicy(), blockedPayload(agent))
  assert.deepEqual(decision, { kind: 'enter', messages: [] })
  assert.equal(session.events.filter((e) => e.type === 'user/message').length, 0)
})

test('en locale: summary and body are English', async () => {
  const agent = makeAgent()
  const { decision, session } = await runPreStep(blockingPolicy(), blockedPayload(agent), { lang: 'en' })
  assert.deepEqual(decision, { kind: 'reject' })
  const notice = session.events.find((e) => e.type === 'user/message')
  assert.equal(notice.data.source.summary, 'Security guard blocked this message')
  assert.ok(notice.data.content[0].text.includes('Your message was blocked by the security guard'))
})

test('a failing session append never breaks the reject (containment)', async () => {
  const agent = {
    id: 'notice-test-session',
    session: { append() { throw new Error('boom') } },
  }
  const { decision } = await runPreStep(blockingPolicy(), blockedPayload(agent))
  assert.deepEqual(decision, { kind: 'reject' })
})
