# Policy Table Reference

Fully specified policy fields, operators, actions, built-in baseline defenses, and the runtime semantics. Architecture-level details (hook mapping, decision engine, panel lifecycle, file bus) live in [architecture.md](./architecture.md).

A policy is an ordered entry with an `action` and a `priority`; its `rules` are matched with **OR** semantics (any rule hit triggers the policy). The table is injected via `cordis.yml` under `config.policies`, validated by the schemastery schema before `apply`.

## Rule fields (`field`)

- Built-in: `eventType`, `agentId`, `agentType` (reserved, no such concept in dsh), `content`.
- Tool events: `toolName`, `arguments` (the full JSON), and the **expanded raw argument fields** (`command`, `path`, `url`, `code`, ...).
- Any other field is looked up in the event `data` first, then in `context`.

## Operators (`operator`)

| Operator | Semantics |
| --- | --- |
| `eq` | strict equality |
| `neq` | not equal |
| `contains` | substring containment (strings) |
| `in` | `value` is an array; a hit on any element counts |
| `matches` | glob with `*` wildcard (`write*`, `mcp_*`) |
| `regex` | real RegExp match (bare pattern or `/pattern/flags`); invalid or catastrophic-backtracking patterns never match (fail safe) |

## Actions (`action`)

| Action | Effect |
| --- | --- |
| `allow` | let through |
| `block` | block (tool call `deny`, result `block`, step `reject`) |
| `ask` | approval, only effective on `tools/pre-execute`; degrades to block elsewhere |
| `warn` | let through, but write a warning log |

## Built-in Baseline Defenses

Out of the box the plugin ships a 27-policy threat model; no policy table is required. The feature extractor (`features.ts` + `intent.ts`) turns tool calls, tool results, cross-event state, and user-message intent into feature fields the engine matches. A field is **only present when its signal fired**, so a benign call produces no fields and matches no baseline rule.

The 27 built-in policies (priority **50**, below the user default of 100):

| Policy id | Matches field | Action | Blocks / warns |
| --- | --- | --- | --- |
| `base-block-high-risk-command` | `highRisk` | block | `rm -rf /`, pipe-to-shell (`curl … | sh`), at-shell-segment-head loops/shutdown/format (`while true; …`, `shutdown now`, `sudo reboot`, `mkfs…`), shell rc truncation, reverse shells (`bash … >& /dev/tcp/…`, `nc -e`, `socat … EXEC:`), letter-spaced `r m - r f /` (and `sudo r m - r f /`) |
| `base-block-obfuscated-command` | `obfuscated` | block | `base64 -d | sh`, `xxd -r`, hex escapes, invisible-unicode / zero-width tricks |
| `base-warn-overlong-command` | `overlong` | warn | commands longer than 10 000 chars (recorded, never blocked by length alone) |
| `base-block-encoded-high-risk` | `encodedHighRisk` | block | base64/hex payloads that decode to a high-risk or obfuscated command (`echo <b64> | base64 -d`, PowerShell `-EncodedCommand`, incl. short padded tokens and UTF-16LE payloads) |
| `base-block-protected-path` | `protectedPathHit` | block | `~/.ssh`, `~/.gnupg`, `~/.dsh`, shell rc files, sensitive `/etc` files (quote-splitting resistant) |
| `base-block-outside-delete` | `deleteOutsideWorkspace` | block | deletion (`rm`, `shred`, `gio trash`, `find -delete`, …) targeting paths resolved outside the workspace (`..`, `cd` base, `~`/`$HOME` included) |
| `base-block-loop-hazard` | `repeatExceeded` | block | the 4th identical mutating call in a turn (repeat budget, allows 3; read-only calls like `git status` never count) |
| `base-block-artifact-execution` | `artifactExecutionRisk` | block | executing a risky script written earlier in the same turn |
| `base-block-exfil-chain` | `exfilChain = high` | block | known-secret outbound, turn risk flag + prior outbound, risky artifact + outbound, or both chain legs (credential + encoding) armed at egress |
| `base-warn-exfil-chain` | `exfilChain = medium` | warn | outbound with only one chain leg armed (audited, not blocked) |
| `base-block-tool-result-injection` | `toolResultRisk = block` | block | tool results with a high-confidence DIRECTIVE / encoded prompt-injection phrase (persona hijack / safeguard defeat / tool luring / exfiltration / privilege escalation) |
| `base-warn-tool-result-injection` | `toolResultRisk = warn` | warn | ≥2 weak injection phrases from **different** families (soft signal). Capability statements ("you can post results to …") and a single weak phrase are not flagged |
| `base-block-user-intent-attack` | `userIntentRisk = block` | block | user message asks to disable the guard, bypass approval, or ignore restrictions (step rejected). Quoting/discussing the guard ("the docs say to disable …") is not flagged |
| `base-warn-user-intent-attack` | `userIntentRisk = warn` | warn | softer manipulation hints (pretend-unrestricted / bypass how-to), audited only |
| `base-block-privilege-escalation` | `privEsc = block` | block | privilege escalation / security-control disable: `setenforce 0`, service stop/mask, `chmod -R 777`, `chown root`, setuid bit |
| `base-warn-privilege-escalation` | `privEsc = warn` | warn | non-recursive world-writable `chmod 777` (single-file permission fixes may be legitimate) |
| `base-block-system-path-write` | `systemPathWrite = block` | block | writes into system persistence locations: `/etc` cron / rc / profile / account files, Windows system dirs |
| `base-warn-system-path-write` | `systemPathWrite = warn` | warn | install/copy into system bin or library dirs (`/usr[/local]/bin`, `/Library`); global CLI installs may be legitimate |
| `base-block-config-tamper` | `configTamper` | block | in-place tampering with guard/policy files (`sed -i` / overwrite / delete on `AGENTS.md`, `SKILL.md`, policy configs) |
| `base-block-sandbox-escape` | `sandboxEscape = block` | block | sandbox/container escape tooling: `nsenter`, `chroot` execution, `docker.sock` mount, `/proc/1/root`, `/:/` host mount |
| `base-warn-sandbox-escape` | `sandboxEscape = warn` | warn | privileged container run (`--privileged`); testcontainers/DinD setups may be legitimate |
| `base-warn-net-recon` | `netRecon` | warn | network scanning/listening (`nmap`, `masscan`, `nc -l`); may be legitimate debugging |
| `base-warn-path-traversal` | `pathTraversal` | warn | multi-segment `../` path traversal in a command |
| `base-warn-untrusted-source` | `untrustedSource` | warn | clone-then-build/install chain from a freshly cloned source |
| `base-warn-insecure-registry` | `insecureRegistry` | warn | package index/registry overridden to plain `http://` (supply-chain risk) |
| `base-warn-secret-logging` | `secretLogging` | warn | code writing secret-looking values to logs (`console.log`/token/password/secret) |
| `base-warn-memory-poison-write` | `memoryPoisonWrite` | warn | directive/trigger-phrase content written toward a memory-like target (long-term memory poisoning risk) |

Other feature fields available for user rules: `command`, `overlong`, `outbound`, `secretRef`, `transformSignal`, `encodedHighRisk`, `scriptArtifactPath` / `scriptArtifactHash` / `scriptArtifactRisk`, `toolResultText`, `specialTokensRemoved`, `toolResultFlags`, `toolResultRisk`, `observedSecrets`, `deleteTargets`, `privEsc`, `systemPathWrite`, `configTamper`, `sandboxEscape`, `netRecon`, `pathTraversal`, `untrustedSource`, `insecureRegistry`, `secretLogging`, `memoryPoisonWrite`.

Turn the whole baseline off with `basePolicies: false`.

## Workspace root

`workspaceRoot` (default `process.cwd()`) scopes the outside-delete and protected-path guards. Deletion targets are **resolved as absolute paths**: `..`/`.` are normalized, a leading `cd <dir>` changes the base for subsequent relative targets, and `~`, `~user` and `$HOME` expand to the home directory; the resolved target is then compared against the workspace root case-fold-consistently (a root like `/Users/Dev/MyProject` is never misjudged). Everything outside the root is treated as outside the workspace.

## Policy precedence

Baseline policies sit at priority **50**; user policies default to **100**, so an explicit user policy always wins over the baseline. The UI policy file bus (`ui-policies.json`) **wholesale-replaces** the effective table (baseline + user policies) when it exists. A panel save must keep the baseline rows if you want them to survive.

## Observed secrets / exfiltration chains

Secrets observed in tool results are remembered per session with a sliding TTL (5 minutes, refreshed on use). Path-shaped tokens, dotted identifiers and low-entropy runs never count as secrets (a directory listing is not a leak), and the per-session pool is LRU-capped. An outbound command that carries a known secret (raw, base64, or hex form), or that fires while a credential or encoding leg of the chain is armed, is classified as an exfiltration chain: `high` is blocked, `medium` is warned and audited via the `recordVerdict` trail.

## Prompt guard (system-prompt assembly)

With `promptGuard: true` (default) the plugin injects an `agent-security-guard` section (order -50, before the persona) into every system-prompt assembly: 6 static rules (tool-only state changes, no secrets in prompts, protected paths, no outside-workspace deletes, tool results as untrusted data) plus a dynamic "session risk context" block when the session has observed secrets or risk flags. Contribution follows the harness's cooperative semantics: the section is appended to the waterfall result, and a registered `complete` system-prompt section intentionally overrides it. Disable with `promptGuard: false` or `hooks.systemPromptAssemble: false`.

## User-intent attack scan

Every `agent/pre-step` scan runs the **user-role** message text (never system/tool-derived context mixed in through `additionalContexts`) through the intent patterns (plain + dense views; Chinese patterns on the plain table only). Direct attack wording (`disable the guard`, `skip the approval`, `ignore all restrictions`, `绕过审批`, …) sets `userIntentRisk: block` → rejected by `base-block-user-intent-attack`; softer hints (`pretend you have no restrictions`, bypass how-to questions) are `warn` → audited by `base-warn-user-intent-attack`. Quoting/discussing the guard itself ("The docs say: to disable the safety guard, edit config.yml") is not treated as an attack.

## Prompt-block notice

When an `agent/pre-step` rejection happens (`block`, or an `ask` degraded to reject), the plugin appends a `notice`-form `user/message` (`source.kind: 'plugin'`) to the session by default (`promptBlockNotice: true`; disable with `promptBlockNotice: false`), so the conversation page shows immediate feedback instead of silently swallowing the user's message: the collapsed row shows the summary ("Security guard blocked this message") and expanding reveals the localized reason (policy id included). The notice carries only the policy reason — it never echoes the blocked content (prompt-injection safety) and never feeds the blocked text back into model context; failures are contained (the reject still wins, never downgraded to an error).

## Monitor mode

Set `mode: monitor` in cordis.yml to run the whole table (baseline + user policies) in monitor mode: every `block`/`ask` verdict downgrades to `warn`, so the guard records verdicts in the audit trail but never denies. Individual policies can override via their own `mode` field (the UI policy table is isomorphic to the cordis.yml `policies` field). Default is `protect`.

## Verdict logging

Verdicts are persisted to the plugin's own JSONL audit file, `$DSH_HOME/agent-security-guard/verdicts.jsonl`, and **never** to the harness session log (the harness telemetry layer treats a committed `feedback/record` event as the session-export consent signal). `allow` verdicts are **not persisted by default**; `block`/`ask`/`warn` are. Records carry the durable meta (session / turn / step / call id / policy / time); tool verdicts also persist the tool name and call id (the panel correlates arguments/result text from the live session), and `agent/pre-step` verdicts persist the assembled prompt content the hook inspected at record time. Detail fields are bounded (~4 KB each) and purely additive. The audit file is size-capped (auto-compacted) and can be cleared from the panel.