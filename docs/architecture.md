# Architecture

Design boundaries, source layout, hook points, decision semantics, the review chain, and the review-panel lifecycle.

## Design boundaries

- **Local bounded synchronous decisions**. `engine.ts` makes no external calls. The verdict path stays bounded per event: the `regex` operator rejects known catastrophic-backtracking patterns (nested/alternation-quantified groups, including `{n}` repetitions) and caps input length, so a synchronous decision does not freeze the harness event loop on the covered shapes. Unknown exotic backtracking patterns are outside the reviewed surface.
- **Local rules only**. Online decisions (a remote policy service) are out of scope for this plugin. If you need one, extend the `engine.decide` call site in `adapter.ts`.
- **No sandbox / heartbeat / metadata reporting**. The plugin only makes local rule decisions and does not include these capabilities.
- **No writes to the harness session log**. Verdicts ride the plugin's own audit file (`verdicts.jsonl`), never `feedback/record`. The harness telemetry layer treats a committed `feedback/record` as the session-export consent signal.
- **Panel API is loopback-only by default**. `/guard/api/*` routes are registered when the webServer binds `127.0.0.1`; a non-loopback binding registers them only when an explicit `webRuntime.trustedHosts` allowlist exists (see "Panel API security").

## Directory layout

The package ships two halves: a **host** half (Node, runs in the harness process) and a **client** half (browser bundle, loaded by the DSH web shell through the package's `dsh.client.inject`).

```
src/
├── index.ts          # Plugin entry: name / Config / apply; wires engine, listeners, file bus, model stage, panel API
├── config.ts         # Config schema (schemastery) + semantic validation + UI policy table + guard preferences
├── types.ts          # GuardPolicy / GuardRule / GuardEvent / GuardDecision
├── engine.ts         # GuardEngine: rule matching, priority, failOpen; setPolicies hot table swap
├── policy-store.ts   # Policy file bus: watch + hot table swap + effective.json mirror
├── guard-api.ts      # Host-half web routes under /guard/api/*
├── adapter.ts        # harness events -> GuardEvent; verdicts -> harness decisions; feature merging
├── features.ts       # Threat feature extraction (static, stateful, tool-result)
├── command-threats.ts# Command/content threat families merged from the operator-rules baseline
├── threat-catalog.ts # Platform-adaptive rule catalogue (shared + posix / win32 / darwin)
├── platform.ts       # Platform resolution: config.platform > DSH_GUARD_PLATFORM > host OS
├── intent.ts         # User-intent attack scan (block / warn risk features)
├── patterns.ts       # Threat pattern library (tool-result injection phrases, secret refs, transforms)
├── secrets.ts        # Observed-secret detection
├── state-store.ts    # Session/turn state with sliding TTL (loop counters, signals, secrets, FIFO cap)
├── base-policies.ts  # Built-in baseline policies (27, priority 50)
├── normalize.ts      # Bounded text normalization (raw / normalized / compact)
├── decode.ts         # Bounded base64/hex/UTF-16LE payload decoding (depth 2, printable filter)
├── prompt-guard.ts   # System-prompt security section builder
├── model-review.ts   # Model review stage: callers, parsers, template rendering, verdict merge
├── audit.ts          # Verdict + model-review recording to the plugin's local JSONL audit file
├── audit-prompts.ts  # The three shipped review templates (malicious intent / risky instruction / intent drift)
├── hooks.ts          # Hook-name canonicalization: native seams, seam metadata
└── client/           # Client half: panel UI (index.tsx), API wrapper (api.ts), locales (locales.ts), slot types (types.ts)
```

## Hook points

The policy table declares the active phase of a policy by hook name. Hook names ARE the native deepseek-harness extension-point seams (`ctx.on` event names); the guard does not introduce an aliasing vocabulary:

| Hook (= deepseek-harness seam) | Mode | Intervening action |
| --- | --- | --- |
| `tools/pre-execute` | waterfall | `deny` / `ask` / allow |
| `tools/post-execute` | waterfall | `block` (corrective feedback) / allow |
| `tools/result` | emit | observe-only (audit log) |
| `agent/pre-step` | waterfall | `reject` / allow |
| `agent/turn-stopping` | awaited notification | `block`/`ask` steer a continuation with the reason (self-capped per turn) |
| `agent/session-start` | emit | observe-only (audit log; cannot gate startup) |
| `subagent/start` / `subagent/end` | emit | observe-only (audit log; keyed to the child session id) |
| `ctx.tools.guard()` | synchronous invariant | `deny`-only (rule stage only), after the whole pre-execute waterfall |

- On `tools/pre-execute`, `ask` maps to `{ kind: 'ask', reason }` through the harness's native approval service (`ctx.get('approval')`). When the approval service is not assembled, the harness degrades `ask` to `deny`.
- `agent/pre-step` and `tools/post-execute` have no approval seam, so `ask` degrades to `reject` and `block` respectively.
- At `agent/turn-stopping` the harness offers no halt, so a blocking verdict steers (`agent.steer`) a continuation message carrying the reason (the same channel the Claude Code `Stop`-hook bridge uses). The guard caps consecutive steers per (session, turn) at 3 and then degrades to audit-only, because the harness stop-loop guard is not shipped yet.
- `ctx.tools.guard()` is registered through the harness's monotonic guard API: it runs after ALL `tools/pre-execute` listeners, may only deny, and cannot be bypassed by listener ordering. The seam is synchronous, so only the rule stage evaluates there.

**Single-hook contract**: the policy editor enforces exactly one hook per policy, with no `*` (all-hooks) option and no multi-select. `ask` is pinned to `tools/pre-execute` (the only hook with an approval seam), so the UI blocks and the save API rejects any `ask` policy bound elsewhere (it would silently degrade to block/reject).

**Panel binding surface**: the policy editor offers ALL nine native seams above. The observe-only seams and the `tools/guard` invariant carry a hover hint explaining what a verdict does there. Review TEMPLATES (model stage) and the baseline scope offer the same nine-seam surface with multi-select: a template joins EVERY listed hook's chain. At the observe-only seams the full pipeline (rules + model) is registered, so the review runs and its verdict is recorded as an audit row without ever interrupting the run (the same posture a policy bound there has); `tools/guard` is synchronous and rule-stage only, so a model binding there is inert (the hover hint says so).

## Decision semantics

1. Select the policies whose `hooks` match the event's `eventType` and that are `enabled` (hook selectors accept exact seam names, `*`, and globs; the panel writes single-hook policies only).
2. Traverse them by `priority` descending (default 100, ties in declaration order).
3. Within a policy, any rule hit means the policy hit (OR semantics).
4. On a hit, return that policy's `action`; nothing hits → default `allow`.
5. Engine exceptions are never thrown onto the hook path; they degrade to allow or block per `failOpen` (default `true`).

## Review chain (rules → model, both pluggable)

The guard chain is `hook → rules → model → verdict` (`src/model-review.ts`). The two stages are independently switchable from the "Security Guard" settings section:

- **Rule stage** (`engine.ts`, `rulesEnabled` preference, default on): synchronous, deterministic, millisecond-level. `setRulesEnabled(false)` short-circuits `decide()` to allow without touching the model stage.
- **Model stage** (`model-review.ts`, `modelReview` preferences, default off): runs after the rule stage on every seam the review templates are bound to, calls a large model with the rendered review prompt, and parses the output into one of the same four actions (`allow` / `warn` / `ask` / `block`).

The model stage reviews through **templates**. Three are shipped (`audit-prompts.ts`): Malicious Intent Detection bound to `agent/pre-step`, and Risky Instruction Detection plus Intent Drift Detection bound to `tools/pre-execute`. Baseline templates are read-only cards on the panel (only the enable switch is editable); custom templates bind one or more hooks through a multi-select, run after the baseline set, and can cap their own disposition with an `action` field (the strictest verdict the template may deliver).

Everything the model stage needs is behind a seam, so the wiring can be swapped without touching the engine:

- `ModelVerdictParser` (`createModelVerdictParser` returns a composite that reads the shipped templates' JSON and two-line plain-text verdict formats, with a generic last-JSON-object fallback): model output → verdict.
- `ModelCaller`: `SessionModelCaller` reuses the session's current model via `ctx.llm` (session mode). In custom mode the configured endpoint is called over one of three wire protocols (`modelReview.protocol`): `openai-chat` (`/chat/completions`, default), `openai-responses` (Responses API), or `anthropic` (Messages API). `createModelCaller` is the swap point for retry/streaming/provider adapters.
- `mergeVerdicts(rule, model)` is the single pure combination policy with **strictest-wins** semantics (`block > ask > warn > allow`): the rule verdict is the floor, so the model can upgrade it but never relax it, and when the model finds something stricter its verdict (and reason) take over. Both stages absent → allow. Template verdicts merge the same way; a `block` short-circuits the remaining templates.

Fail-open posture is preserved end to end: a missing/disabled model stage, a caller timeout (`timeoutMs`, default 12000 ms), an unparseable output, or an unavailable session route all degrade to the rule verdict. **Short-circuit:** `block` is the strictest verdict the model could ever produce, so a rule `block` skips the model call entirely; only `ask`/`warn`/`allow` rule verdicts (or a disabled rule stage) consult the model, which can only confirm or escalate.

Session mode resolves the model route from the session log. On the very first request of a session the route may not be there yet, so the event is skipped and recorded as `status: 'skipped'`. With `modelReview.makeupReview` on (default off, session mode only), skipped events park in a bounded in-memory queue and get reviewed once the route shows up.

Every model-review attempt is appended to the audit file as a `kind: 'model'` row (provider, rendered request, raw response, duration, status), so the Security Review tab shows the model stage's procedure. `allow` rows follow the same "record allow verdicts" switch as merged verdicts; `error` and `skipped` rows always persist.

The model stage writes its reason in the panel language (`lang` is passed to the stage); fixed verdict labels inside stored reasons are localized on read by the adapter.

Demo API-key note: `modelReview.apiKey` is stored in the settings document (plaintext). The `createModelCaller` seam is where a later iteration moves the key into the harness `credentials` service.

## Panel lifecycle

The panel is a **static web plugin**, not a `dynamicCordisRunner` plugin. The host half registers `/guard/api/*` routes (`guard-api.ts`) and the client half is the `dsh.client` bundle (`src/client`, compiled to `lib/client.js` by tsdown). There is no per-process approval prompt, no dynamic-runner session anchoring, and the client never leaves its anchor session.

- **Header utility slot**: the client registers one session-scoped slot, `conversation.session.header.utilities`: a compact shield button with a live deny-count badge on every open session's header. Pressing it opens the panel. It is present only while the `showHeaderButton` preference is on; toggling the setting registers and unregisters the seat live. The seat deliberately does **not** use `sidebar.footer.action`, which is a horizontal flex row already occupied by the built-in Cordis panel entry at full width; a second full-width item would be pushed out and clipped by the app frame.
- **Security Review tab**: the client also registers a session-scoped tab into the `conversation.view` ring (beside Trajectory), present while the `showSessionTab` preference is on. Each session gets its own tab showing only that session's verdicts (sub-agent sessions included), polled every 4 s while open. Both toggles live in the "Security Guard" settings section, next to the master switch (`guardEnabled`), the rule-stage switch (`rulesEnabled`), and the allow-recording switch (`recordAllow`); all of them take effect on the next event without a reload. If the active tab is removed, the conversation shell falls back to the default Chat view.

### Panel API security

Because `/guard/api/*` carries session context AND control ability (policy-table replacement, master switch), it is guarded:

- **Loopback-only Host** with correct IPv6 `[::1]` parsing and 127.0.0.0/8 acceptance, UNION the explicit `webRuntime.trustedHosts` allowlist (the bind-derived LAN literals of an all-interfaces assembly plus any `dsh web --trusted-host` authorities). Loopback stays accepted even when an allowlist exists, so the allowlist only ever widens the fence; a spoofed or rebound `Host` is refused.
- `Sec-Fetch-Site: cross-site` and a mismatched `Origin` are rejected (the Origin hostname must be loopback or allowlisted and must match the request Host).
- Official mutation requests must carry a `Content-Type: application/json` body (blocking CORS-safelisted "simple request" CSRF).
- Every mutation additionally requires a per-process unpredictable CSRF token issued to the page as a `SameSite=Strict` cookie (double submit). A cross-site page never carries it.
- When `webServer.host` is not `127.0.0.1`, the panel API is registered **only** if a `trustedHosts` allowlist exists. Without one the routes are not registered at all (no session plaintext or control route is exposed to the network).

### Verdict audit file

Verdicts are written to the plugin's own audit file `$DSH_HOME/agent-security-guard/verdicts.jsonl` (JSONL, `audit.ts`; append-only, `allow` not persisted by default). The panel polls it and folds each row against live-session context (tool call/result, per-step prompts, approval outcomes). Each row carries the durable meta (session / turn / step / call id / policy / time); tool verdicts also persist the tool name and call id, and `agent/pre-step` verdicts persist the assembled prompt content the hook inspected at record time. Detail fields are bounded (~4 KB each). Model-review attempts land in the same file as `kind: 'model'` rows. The file survives restarts; a session that is no longer live contributes its stored rows without detail. Growth is capped at 4 MB: past the cap, a compaction rewrites the file keeping only the newest half, and the panel can clear the file.

### Online configuration file bus

Online edits go through a file bus. The plugin never modifies the harness and adds no new agent attack surface (the client half is fixed strings, unreachable by the model):

```
$DSH_HOME/agent-security-guard/          # DSH_HOME defaults to ~/.dsh
├── ui-policies.json   # written by the host half on panel save (main plugin is read-only, watch hot-reloads it)
├── effective.json     # mirror of the currently effective table, written by the main plugin (panel displays it read-only)
└── verdicts.jsonl     # plugin-owned verdict audit file, written by audit.ts (panel folds it against live sessions)
```

Semantics:

- `ui-policies.json` exists and is valid → **wholesale-replaces** the cordis.yml policy table (no merging); absent → the cordis.yml baseline is in effect.
- "Restore cordis.yml baseline" writes a `{"v":1,"reset":true}` marker; after the store restores the baseline it deletes the file.
- Corrupted / schema-invalid / semantically-invalid file → keep the last good policy table; the error is written to `effective.json.error` and shown in the panel; the guard does not stop.
- Takes effect within about 1 second after saving (the watch poll interval), no restart needed.

Hand-editing `ui-policies.json` is fully supported under the same semantics. The panel is just its editor. The format is `{v: 1, policies: [...]}` and `policies` is isomorphic to the cordis.yml `policies` field.

> Permission note: the UI operator thereby gains the ability to modify this machine's runtime guardrails, equivalent to their existing privileges (they can already modify cordis.yml and approve dynamic plugins). If your threat model requires the UI operator to be unable to change rules, do not register the panel at the assembly layer, or split the read/write plugins for independent approval.

### Language preference

The plugin registers the `agent-security-guard` settings namespace so the DSH Settings shell can render the language picker (`auto` / `zh` / `en`). The panel client reports the active DSH locale back through `POST /guard/api/lang/resolved`, so `auto` follows the DSH locale instead of falling back to English. Deployments without a settings service fall back to the schema default (`auto`, English).

The resolved language also decides the language of verdict reasons: rule reasons are stored as English strings with a Chinese translation table (`REASON_ZH` in `adapter.ts`) and localized at render time, and the model stage asks the model to write its reason in the panel language directly.
