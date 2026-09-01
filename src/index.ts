/**
 * deepseek-harness security-guard plugin: TypeScript-only local decision
 * logic.
 *
 * The plugin subscribes to the NATIVE deepseek-harness extension points (the
 * `ctx.on` seam names, no aliasing vocabulary) and keeps the whole engine
 * running locally with the harness:
 *
 *   - `src/engine.ts`: the rule engine (eq/neq/contains/in/matches, OR
 *                        semantics, priority ordering, fail-open/closed);
 *   - `src/adapter.ts`: normalizes harness payloads onto the engine and maps
 *                        verdicts back onto the seams' decision types;
 *   - `src/config.ts`: the policy table schema and fail-loud validation.
 *
 * Interception surface (hook = native harness seam):
 *
 *   Verdict-capable:
 *   - `tools/pre-execute`   (deny / ask / delegate a tool call)
 *   - `tools/post-execute`  (block / enrich a tool result)
 *   - `agent/pre-step`      (reject / delegate a proposed model step)
 *   - `agent/turn-stopping` (block steers a continuation at the stop boundary,
 *                             self-capped per turn)
 *   - `ctx.tools.guard()`   (monotonic deny-only invariant, rule stage only)
 *
 *   Observe-only (audit trail):
 *   - `tools/result` / `agent/session-start` / `subagent/start` / `subagent/end`
 *
 * The Security-Guard Review panel is a STATIC web plugin: the host half is
 * `registerGuardApi` (webServer routes under /guard/api, see guard-api.ts)
 * and the client half is the `dsh.client` bundle `src/client` (compiled to
 * lib/client.js by tsdown, loaded by the web shell at boot through the
 * package's `dsh.client.inject` declaration). No `dynamicCordisRunner` is
 * involved, so there is no per-process approval prompt and no session
 * anchoring / steering message. See the module docs in guard-api.ts and
 * src/client/index.tsx.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard
 */

import { settingsNamespace } from '@deepseek-ai/dsh-settings'
import type { Context } from '@deepseek-ai/cordis'
import { registerListeners } from './adapter.ts'
import { GuardPrefs, GUARD_PREFS_DEFAULTS, GUARD_PREFS_NS, resolveHookSwitches, validatePolicies } from './config.ts'
import type { Config, GuardPrefs as GuardPrefsValue, ModelReviewPrefs } from './config.ts'
import { GuardEngine } from './engine.ts'
import { baselinePolicies } from './base-policies.ts'
import { GuardStateStore } from './state-store.ts'
import { resolve } from 'node:path'
import { PolicyFileStore, policyStorePaths } from './policy-store.ts'
import { registerGuardApi } from './guard-api.ts'
import { recordModelReview } from './audit.ts'
import {
  DefaultModelStage,
  ModelReviewEngine,
  createModelCaller,
  createModelVerdictParser,
} from './model-review.ts'
import type { LlmLike } from './model-review.ts'

export { Config } from './config.ts'
export { GuardEngine } from './engine.ts'
export type * from './types.ts'

/** Cordis plugin name used by loader diagnostics. */
export const name = 'agent-security-guard'

/**
 * Register the guard's listeners and construct the engine.
 * @param ctx - plugin context; listeners are scoped to it and disposed with it.
 * @param config - validated {@link Config}; `policies` is re-checked fail-loud here.
 */
export function apply(ctx: Context, config: Config): void {
  // The schema's .default() guarantees these are set after validation.
  const base = (config.basePolicies ?? true) ? baselinePolicies() : []
  const policies = [...base, ...(config.policies ?? [])]
  validatePolicies(policies)

  const engine = new GuardEngine(policies, config.failOpen ?? true, config.mode ?? 'protect')
  // Legacy v0.1.x hook-switch keys resolve through their native counterparts.
  const hooks = resolveHookSwitches(config.hooks)
  const state = new GuardStateStore()
  const workspaceRoot = resolve(config.workspaceRoot ?? process.cwd())

  // Policy file bus (UI online configuration): $DSH_HOME/agent-security-guard/
  // If ui-policies.json exists it wholesale-replaces the table above; if it is
  // missing/reset, the cordis.yml baseline is in effect; the panel writes that
  // file through the /guard/api routes and watchFile hot-reloads it.
  // See policy-store.ts.
  const storePaths = policyStorePaths()

  // Whether `allow` verdicts are recorded. The persisted preference (settings
  // namespace, default false) is reflected here lazily so a toggle takes effect
  // on the very next event, without a restart or a policy swap.
  let recordAllow = false

  // Panel language for the deny/ask reasons the harness surfaces to the user.
  // Resolved lazily; the panel client seeds the DSH locale through the
  // `/guard/api/lang/resolved` route (`resolvedLocale`), so `auto` follows the
  // active DSH locale instead of falling to English. An explicit `zh`/`en`
  // preference (or the lack of a reporting client) still wins through the
  // fallback below.
  let resolvedLocale: 'zh' | 'en' | undefined
  const lang = (): 'zh' | 'en' =>
    resolvedLocale ?? (guardPrefsFace?.get().locale === 'zh' ? 'zh' : 'en')

  // ── Model review stage (pluggable stage #2) ───────────────────────────
  // The model stage reads its config live (per event) so settings toggles take
  // effect on the very next event. The harness `llm` service is resolved lazily
  // from the plugin context (a headless deployment without an llm provider
  // leaves it absent → session mode fails open to the rule verdict).
  //
  // Demo API-key storage note: the key lives in the settings document
  // (plaintext). The extension seam is createModelCaller; a later iteration
  // may move the key into the harness `credentials` service.
  let modelReviewPrefs: ModelReviewPrefs = { ...GUARD_PREFS_DEFAULTS.modelReview }
  // cordis `ctx.get` returns undefined (never throws) for an unprovided service;
  // absent llm → session mode fails open to the rule verdict.
  const llm = (): LlmLike | undefined => ctx.get('llm') as LlmLike | undefined
  const modelStage = new DefaultModelStage({
    config: () => modelReviewPrefs,
    // Reason-line language: follows the panel language (zh → the model writes
    // its reason in Chinese; otherwise English), so ask/block reasons handed
    // to the user read in the UI language.
    lang: () => lang(),
    caller: () => {
      const llmService = llm()
      return createModelCaller(modelReviewPrefs, llmService !== undefined ? { llm: llmService } : {})
    },
    parser: createModelVerdictParser(),
    // Observability seam: persist every model-review attempt (provider /
    // request body / response body / duration) into the same audit file as a
    // `kind: 'model'` row, so the Security Review tab can show the model
    // stage's procedure. `allow` model rows follow the same
    // "record allow verdicts" switch as merged allow verdicts; error rows (a
    // failed review) always stay.
    onReview: (record) => {
      try {
        recordModelReview(ctx, record, storePaths.verdictLogPath, { recordAllow })
      } catch (error) {
        ctx.logger.warn(`[agent-security-guard] failed to record model review: ${error instanceof Error ? error.message : String(error)}`)
      }
    },
  })
  const pipeline = new ModelReviewEngine(engine, modelStage)

  registerListeners(ctx, engine, hooks, {
    state,
    workspaceRoot,
    promptGuard: config.promptGuard ?? true,
    promptBlockNotice: config.promptBlockNotice ?? true,
    verdictLogPath: storePaths.verdictLogPath,
    recordAllow: () => recordAllow,
    lang,
    pipeline,
  })
  const store = new PolicyFileStore({
    dir: storePaths.dir,
    basePolicies: policies,
    engine,
    logger: ctx.logger,
  })
  store.start()
  ctx.effect(() => () => { store.stop() }, 'policy-store-stop')

  // Panel language preference: register the `agent-security-guard` settings
  // namespace so the DSH Settings shell can render the language picker. The
  // DSH settings RPC domain only serves allowlisted namespaces, so the client
  // reaches this namespace through the plugin's own fenced routes below
  // (`/guard/api/lang`), which call the seam in-process. Deployments without a
  // settings service never fill the face and the panel falls back to the
  // schema default (`auto`);
  let guardPrefsFace:
    | { get(): GuardPrefsValue; update(patch: Partial<GuardPrefsValue>): Promise<void> }
    | undefined
  ctx.inject(['settings'], (sctx) => {
    const ns = settingsNamespace(GUARD_PREFS_NS)
    const scope = sctx.settings.register(ns, GuardPrefs) as {
      get(): GuardPrefsValue
      update(patch: object): Promise<void>
      watch(callback: (next: GuardPrefsValue, prev: GuardPrefsValue) => void): () => void
    }
    guardPrefsFace = {
      get: () => scope.get(),
      update: (patch) => scope.update(patch),
    }
    // Sync the engine master switch, the allow-recording preference, the
    // rule-stage switch and the model-review config from the persisted
    // settings: the toggles in the DSH Settings shell land here live
    // (scope.watch) and take effect on the very next event. No reload, no
    // policy swap.
    engine.setEnabled(scope.get().guardEnabled)
    engine.setRulesEnabled(scope.get().rulesEnabled)
    recordAllow = scope.get().recordAllow
    modelReviewPrefs = scope.get().modelReview
    const unWatch = scope.watch((next) => {
      engine.setEnabled(next.guardEnabled)
      engine.setRulesEnabled(next.rulesEnabled)
      recordAllow = next.recordAllow
      modelReviewPrefs = next.modelReview
    })
    ctx.effect(() => unWatch, 'guard-prefs-watch')
  })

  // Panel host half: webServer routes /guard/api/*. The client bundle calls
  // them with fetch; the write path goes through the same `PolicyFileStore`
  // code that already writes effective.json (fixed path, atomic rename,
  // watcher-hot-reloaded), giving permission semantics consistent with the
  // old vm bridge, minus the sandbox indirection (the main plugin has native fs).
  //
  // The plugin must NOT declare `inject: ['webServer']`: it also runs
  // headless, where webServer never exists and a service wait would keep the
  // fiber pending forever and disable the guard engine. Instead we try to
  // register immediately and, when the service is not (yet) provided,
  // subscribe to the cordis `internal/service` event. `ctx.provide()` fires
  // it the moment the provider fiber activates (state 2), so routes mount
  // exactly when the web shell comes up and never in headless runs.
  // A non-loopback bind additionally needs `webRuntime.trustedHosts`; that
  // service mounts after webServer, so this listens for it too. Registration
  // is scoped to this context and disposed with it.
  const guardApiDeps = {
    paths: storePaths,
    writeUiPolicies: (content: string) => { store.writeUiPolicies(content) },
    getPrefs: (): GuardPrefsValue => guardPrefsFace?.get() ?? { ...GUARD_PREFS_DEFAULTS },
    updatePrefs: async (patch: Partial<GuardPrefsValue>): Promise<void> => {
      if (!guardPrefsFace) throw new Error('settings service not available')
      await guardPrefsFace.update(patch)
    },
    lang: () => lang(),
    reportResolvedLocale: (locale: 'zh' | 'en') => { resolvedLocale = locale },
  }
  let routesInstalled = false
  const installRoutes = () => {
    if (routesInstalled) return
    const disposer = registerGuardApi(ctx, guardApiDeps)
    if (disposer === null) return
    routesInstalled = true
    ctx.effect(() => disposer, 'guard-api-routes')
  }
  installRoutes()
  if (!routesInstalled) {
    ctx.on('internal/service', (name: string) => {
      if (name === 'webServer' || name === 'webRuntime') installRoutes()
    })
  }

  ctx.logger.info(`[agent-security-guard] loaded ${policies.length} policies (${base.length} baseline, `
    + `failOpen=${config.failOpen ?? true}, policy file bus: ${storePaths.uiPoliciesPath})`)
}
