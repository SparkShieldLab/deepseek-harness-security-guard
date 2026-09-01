/**
 * tsdown build for deepseek-harness-security-guard — one browser client bundle.
 *
 * The host half (src/index.ts, guard-api.ts, policy-store.ts, ...) is
 * compiled by tsc directly (lib/*.js, lib/*.d.ts); only the client half is
 * bundled here, as the static-web plugin bundle the web shell's module
 * loader consumes:
 *
 *   entry  src/client/index.tsx  ->  lib/client.js
 *
 * The artifact is a CJS closure factory registered through
 * `window.__ModuleLoader__.load({ id: <package name>, factory: (require) =>
 * ... })` — the official DSH client-bundle contract (see
 * deepseek-harness-master/packages/client/modules/README.md). The loader
 * resolves value imports from its frozen module table: `react` (and the
 * jsx-runtime alias) are externals, everything else in the bundle is
 * inlined. `src/client` imports no other @deepseek-ai package at value
 * level (types.ts is a pure-type structural mirror), so no purity-gate
 * special-casing is needed beyond the node-builtin guard below.
 *
 * `codeSplitting: false` keeps the artifact a single script; there are no
 * lazy chunks in this plugin.
 *
 * Types ship from lib/types (tsc -p tsconfig.client.json), not from tsdown.
 */
import { builtinModules } from 'node:module'
import type { UserConfig } from 'tsdown'

/** Node builtins must never survive into the browser module-loader factory. */
const NODE_BUILTINS = new Set([
  ...builtinModules,
  ...builtinModules.map(id => `node:${id}`),
])

/** Module-table entries the web shell shares into the frozen module table. */
const CLIENT_EXTERNALS = [
  'react',
  'react/jsx-runtime',
]

/** A minimal purity gate: no node builtins, no cross-plugin value imports. */
function purityGate(): NonNullable<UserConfig['plugins']> {
  return {
    name: 'deepseek-harness-security-guard-client-purity',
    resolveId(source: string) {
      if (NODE_BUILTINS.has(source)) {
        throw new Error(
          `client bundle purity: Node builtin "${source}" cannot run in the browser module table — `
          + 'select the dependency browser export or add an explicit browser implementation',
        )
      }
      if (!source.startsWith('@deepseek-ai/')) return null
      if (CLIENT_EXTERNALS.includes(source)) return null
      throw new Error(
        `client bundle purity: "${source}" is not a platform module — cross-plugin value imports are forbidden; `
        + 'collaborate through cordis services (type-only imports are erased and never reach this gate)',
      )
    },
  }
}

export default {
  entry: { client: 'src/client/index.tsx' },
  outDir: 'lib',
  format: 'cjs',
  platform: 'browser',
  dts: false,
  sourcemap: true,
  clean: false, // tsc emitted lib/types first; never wipe it
  external: [...CLIENT_EXTERNALS],
  define: {
    'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV ?? 'production'),
    'import.meta.env.MODE': JSON.stringify(process.env.NODE_ENV ?? 'production'),
    'import.meta.env': JSON.stringify({ MODE: process.env.NODE_ENV ?? 'production' }),
    'import.meta.resolve': 'undefined',
  },
  inputOptions: {
    resolve: {
      conditionNames: ['browser', 'import', 'require', 'default'],
    },
  },
  // External wins for module-table entries; every other dependency inlines.
  noExternal: (id: string) => (CLIENT_EXTERNALS.includes(id) ? undefined : true),
  plugins: [purityGate()],
  outputOptions: {
    entryFileNames: 'client.js',
    banner: `window.__ModuleLoader__.load({ id: ${JSON.stringify('@spark-shield-lab/deepseek-harness-security-guard')}, factory: (require) => {`,
    footer: 'return module.exports; } });',
    intro: 'var module = { exports: {} }; var exports = module.exports;',
    codeSplitting: false,
  },
} satisfies UserConfig
