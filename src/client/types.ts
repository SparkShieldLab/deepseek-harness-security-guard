/**
 * Client-side structural types for the Security-Guard Review panel.
 *
 * The client bundle is a module-table consumer only: every value import must
 * resolve from the web shell's frozen module table (react is the only value
 * dependency), so the cordis `Context` shape below is declared structurally
 * instead of importing @deepseek-ai/cordis (which the bundle's purity gate
 * would reject, since it is not a platform module).
 *
 * Only the slices the panel touches are restated: the slots service
 * (`ctx.slots.inject` / `ctx.slots.register`) used to mount the
 * `conversation.session.header.utilities` seat. No timer service exists in
 * the static client runtime. The panel uses browser timers directly.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/client
 */

/** The slots service face (structural mirror of the client SlotRegistry). */
export interface GuardSlotsService {
  /**
   * Run a callback for each declaration lifetime of a slot: the callback runs
   * synchronously once the slot is declared (and again after a re-declare).
   * The callback may return a single disposer or an iterable of disposers
   * (installed transactionally, disposed in reverse order on collapse).
   */
  inject(key: string, callback: () => (() => void) | Iterable<() => void>): () => void
  /**
   * Register one seat in a slot (returned disposer removes it).
   * `component` is a React component; the `inject` factory supplies props.
   */
  register(options: Record<string, unknown>, component: unknown): () => void
}

/**
 * The client cordis context (structural subset). The locale service is
 * provided by @deepseek-ai/dsh-client-locale; the settings shell section is
 * mounted through the `settings.section` slot (registered via the same slots
 * service, contract owned by @deepseek-ai/dsh-client-ui-settings).
 */
export interface GuardClientContext {
  slots: GuardSlotsService
  /** DSH locale service: active locale snapshot + live subscription. */
  locale: GuardLocaleService
  /** DSH-vendored lifecycle helper: cleanup runs at disposal. */
  effect(fn: () => void | (() => void), label?: string): void
}

/** The DSH locale runtime face the panel reads (active locale + live subscribe). */
export interface GuardLocaleService {
  /** Current immutable locale snapshot (locales, active, revision). */
  getSnapshot(): { active: string }
  /** Notified on snapshot changes (locale switch or dictionary registration). */
  subscribe(fn: () => void): () => void
}

/** Owner props every `settings.section` seat receives from the shell. */
export interface GuardSettingsSectionProps {
  /** Close the settings panel (the shell owns the open state). */
  close: () => void
}
