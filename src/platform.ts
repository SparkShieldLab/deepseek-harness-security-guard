/**
 * Runtime platform detection for the guard's threat-rule catalog.
 *
 * The guard reasons over command/path TEXT, so "platform adaptation" is the
 * choice of which rule set to arm: the same binary ships everywhere and picks
 * its catalog from the host OS at process start. `process.platform` is a
 * process constant, so the catalog is resolved once (see {@link resolvePlatform}
 * + `threat-catalog.ts`) and never changes mid-run.
 *
 * Precedence: an explicit config value wins; otherwise the
 * `DSH_GUARD_PLATFORM` env override (tests / forced shells); otherwise the
 * host platform. Anything that is not `win32` or `darwin` normalizes to
 * `linux` (POSIX family), which is also the only sensible default for the
 * many Node platforms that reuse the POSIX catalogue.
 *
 * @module @spark-shield-lab/deepseek-harness-security-guard/platform
 */

/** The three rule families the catalogue is adapted to. */
export type GuardPlatform = 'win32' | 'linux' | 'darwin'

/** Accepted `platform` config values (`auto` follows the host). */
export type GuardPlatformConfig = 'auto' | GuardPlatform

/** Narrow an arbitrary string to a {@link GuardPlatform}, or `undefined`. */
function asPlatform(value: string | undefined): GuardPlatform | undefined {
  return value === 'win32' || value === 'linux' || value === 'darwin' ? value : undefined
}

/** The host platform, normalized onto the three catalog families. */
export function detectPlatform(): GuardPlatform {
  if (process.platform === 'win32') return 'win32'
  if (process.platform === 'darwin') return 'darwin'
  return 'linux'
}

/**
 * Resolve the active platform. An explicit config value wins; else the
 * `DSH_GUARD_PLATFORM` env override (none of the platforms match → ignored);
 * else the host platform.
 */
export function resolvePlatform(configured: GuardPlatformConfig | undefined = 'auto'): GuardPlatform {
  const explicit = asPlatform(configured)
  if (explicit !== undefined) return explicit
  return asPlatform(process.env.DSH_GUARD_PLATFORM) ?? detectPlatform()
}

/** Whether the platform is a POSIX family (Linux and macOS share the base rules). */
export function isPosix(platform: GuardPlatform): boolean {
  return platform !== 'win32'
}
