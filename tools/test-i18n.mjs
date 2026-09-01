// node:test suite pinning the i18n dual tables (runs against lib/ after
// `npm run build`):
//   - every built-in baseline policy message (base-policies.ts) must have an
//     exact `REASON_ZH` entry (or a dynamic-prefix match), so a message
//     rewording fails here instead of silently dropping the Chinese copy;
//   - every `REASON_ZH` entry keyed by a baseline message must still be USED
//     (stale entries for renamed messages are flagged for cleanup).
//
// Usage: npm run build && node --test tools/test-i18n.mjs

import test from 'node:test'
import assert from 'node:assert/strict'
import { baselinePolicies } from '../lib/base-policies.js'
import { REASON_ZH, REASON_ZH_PREFIXES } from '../lib/adapter.js'

test('i18n: every baseline policy message has a Chinese translation', () => {
  const missing = []
  for (const policy of baselinePolicies()) {
    const message = policy.message
    const exact = Object.hasOwn(REASON_ZH, message)
    const prefixed = REASON_ZH_PREFIXES.some((p) => message.startsWith(p.prefix))
    if (!exact && !prefixed) missing.push({ id: policy.id, message })
  }
  assert.deepEqual(missing, [], 'every baseline message must be covered by REASON_ZH')
})

test('i18n: no stale REASON_ZH entries pointing at removed baseline messages', () => {
  const live = new Set(baselinePolicies().map((p) => p.message))
  const stale = Object.keys(REASON_ZH).filter((key) => key.includes('security baseline') && !live.has(key))
  assert.deepEqual(stale, [], 'baseline-worded REASON_ZH keys must track base-policies.ts verbatim')
})
