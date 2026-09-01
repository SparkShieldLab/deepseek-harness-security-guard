// node:test suite for adapter boundary behaviors (runs against lib/ after
// `npm run build`):
//   1. `agent/pre-step` must NOT serialize the full session history into
//      `data.messages` every step — only a bounded tail (R4 regression).
//   2. `agent/turn-stopping` blocks suppressed by the stop-steer cap must be
//      recorded with a `note`, not as an executed block (R5 regression).
//
// Usage: npm run build && node --test tools/test-adapter-boundaries.mjs

import test from 'node:test'
import assert from 'node:assert/strict'
import { Context } from '@deepseek-ai/cordis'
import { Session, SessionId } from '@deepseek-ai/dsh-session'
import { GuardEngine } from '../lib/engine.js'
import { registerListeners } from '../lib/adapter.js'
import { GuardStateStore } from '../lib/state-store.js'
import { readVerdictLog } from '../lib/audit.js'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/** A user-role message in the harness shape (mirrors createUserMessage output). */
function userMessage(text) {
  return { role: 'user', content: [{ type: 'text', text }], source: { kind: 'user' } }
}

test('pre-step: data.messages is a bounded tail, not the full history (R4)', async () => {
  const ctx = new Context()
  const captured = []
  const engine = new GuardEngine([])
  registerListeners(ctx, engine, {}, {
    state: new GuardStateStore(),
    pipeline: {
      evaluate: async (event) => {
        captured.push(event)
        return { action: 'allow', matchedRules: [], message: 'ok' }
      },
    },
  })

  // A long session: 400 ~1KB user messages plus one distinctive newest turn.
  const firstText = 'OLDEST-MESSAGE-MARKER ' + 'a'.repeat(1000)
  const lastText = 'NEWEST-MESSAGE-MARKER please review this'
  const messages = [
    userMessage(firstText),
    ...Array.from({ length: 400 }, (_, i) => userMessage(`filler message ${i} ${'b'.repeat(1000)}`)),
    userMessage(lastText),
  ]
  const agent = { id: 'boundaries-session', session: Session.create(SessionId('boundaries-session')) }
  await ctx.waterfall(agent, 'agent/pre-step', { agent, messages, turn: 1, step: 1 }, async () => ({ kind: 'enter', messages: [] }))

  assert.equal(captured.length, 1, 'exactly one pre-step event reached the pipeline')
  const raw = captured[0].data.messages
  assert.ok(typeof raw === 'string' && raw.length > 0, 'data.messages still carries a canonical payload')
  assert.ok(raw.length <= 64_000, `the serialized tail must be bounded (got ${raw.length} chars)`)

  const parsed = JSON.parse(raw)
  assert.ok(Array.isArray(parsed), 'the tail stays valid JSON (userQueryOf must keep parsing it)')
  assert.ok(parsed.length < messages.length, 'early history is dropped, only the tail survives')
  const joined = raw
  assert.ok(joined.includes('NEWEST-MESSAGE-MARKER'), 'the newest user message is always inside the tail')
  assert.ok(!joined.includes('OLDEST-MESSAGE-MARKER'), 'the oldest message falls out of the bounded tail')
})

test('turn-stopping: blocks suppressed by the stop-steer cap are annotated, not shown as executed (R5)', async () => {
  const ctx = new Context()
  const dir = mkdtempSync(join(tmpdir(), 'guard-boundaries-'))
  const logPath = join(dir, 'verdicts.jsonl')
  const steered = []
  const agent = {
    id: 'stop-boundaries-session',
    session: {
      events: [{ type: 'assistant/message', data: { message: { content: [{ type: 'text', text: 'final answer' }] } } }],
    },
    steer: (message) => { steered.push(message) },
  }
  registerListeners(ctx, new GuardEngine([]), {}, {
    state: new GuardStateStore(),
    verdictLogPath: logPath,
    recordAllow: () => false,
    pipeline: {
      evaluate: async () => ({ action: 'block', matchedRules: ['p'], message: 'stop boundary blocked', policyId: 'p' }),
    },
  })

  try {
    // STOP_STEER_CAP is 3: the first three blocks steer, the fourth is suppressed.
    for (let i = 0; i < 4; i++) {
      await ctx.parallel('agent/turn-stopping', { agent, turn: 7 })
    }

    assert.equal(steered.length, 3, 'steer fires exactly up to the cap')
    const rows = readVerdictLog(logPath)
    assert.equal(rows.length, 4, 'every block verdict is audited, including the suppressed one')
    for (const row of rows.slice(0, 3)) {
      assert.equal(row.note, undefined, 'executed steers carry no suppression note')
    }
    const suppressed = rows[rows.length - 1]
    assert.equal(suppressed.action, 'block')
    assert.ok(typeof suppressed.note === 'string' && suppressed.note.toLowerCase().includes('suppress'), 'the capped block is annotated as suppressed')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
