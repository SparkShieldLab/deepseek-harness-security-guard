#!/usr/bin/env bash
#
# build.sh — build lib/ from src/ for the deepseek-harness-security-guard plugin.
#
# Dependencies: Node.js >= 22, npm. A plain `npm install` provides the dev
# toolchain (typescript, tsdown, @types/react, @types/node) and the
# type/type-scope @deepseek-ai/* packages declared in package.json.
#
# Version alignment with the RUNNING dsh harness:
#   The plugin's sources import @deepseek-ai/* packages that must match the
#   harness runtime APIs. `npm install` pulls the versions published to the
#   registry, which can be OLDER than the local harness runtime — the compile
#   would type-check against different APIs than the running process. When a
#   `dsh` installation exists, build.sh type-checks @deepseek-ai imports
#   against the dsh installation's own node_modules via a generated tsconfig
#   `paths` override:
#
#     1. locate dsh (override with DSH_NODE_MODULES=/path/to/dsh/node_modules)
#     2. write a throwaway tsconfig that maps @deepseek-ai/* types to the
#        dsh install (type-checking only — node_modules is never touched)
#     3. compile: tsc -p <host config>  (src/ -> lib/) + tsdown (client)
#     4. verify the build output; optionally run the test suite
#
#   When NO dsh is present (e.g. a clean CI clone), the build falls back to
#   the registry-pinned @deepseek-ai under node_modules and logs a warning —
#   cross-version type drift is the operator's responsibility then.
#
#   IMPORTANT (N15): node_modules must NEVER be mutated to point at the dsh
#   install (no symlinks, no copies). `npm install` reify follows symlinks
#   inside node_modules and would wipe the dsh install's own @deepseek-ai
#   packages — this destroyed a real dsh installation during review. Type
#   alignment is therefore type-check-only via `paths`.
#
# Usage:
#   ./build.sh            build lib/ and run tests
#   ./build.sh --no-test  build lib/ only, skip tests
#   DSH_NODE_MODULES=/path/to/dsh/node_modules ./build.sh   # override dsh path
#
set -euo pipefail

# ---------------------------------------------------------------------------
# 0. Locate the plugin root (directory containing this script).
# ---------------------------------------------------------------------------
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

RUN_TESTS=1
for arg in "$@"; do
	case "$arg" in
		--no-test) RUN_TESTS=0 ;;
		--test) RUN_TESTS=1 ;;
		*) echo "build.sh: unknown argument: $arg" >&2; exit 2 ;;
	esac
done

# ---------------------------------------------------------------------------
# 1. Ensure the toolchain is installed.
# ---------------------------------------------------------------------------
if [[ ! -x node_modules/.bin/tsc || ! -x node_modules/.bin/tsdown ]]; then
	echo "==> missing tsc/tsdown — run 'npm install' first (Node >= 22, npm)." >&2
	exit 1
fi

# ---------------------------------------------------------------------------
# 2. Align @deepseek-ai/* types with the running dsh installation.
#    Type-only alignment via a generated tsconfig `paths` override. node_modules
#    is never mutated: a symlink there makes `npm install` reify follow it and
#    wipe the dsh install's own @deepseek-ai packages (N15, observed in review).
#    Without a local dsh the plain tsconfig.json is used (registry-pinned
#    types from node_modules).
# ---------------------------------------------------------------------------
if [[ -n "${DSH_NODE_MODULES:-}" ]]; then
	if [[ ! -d "$DSH_NODE_MODULES/@deepseek-ai" ]]; then
		echo "build.sh: cannot find @deepseek-ai packages under:" >&2
		echo "  $DSH_NODE_MODULES" >&2
		exit 1
	fi
elif command -v dsh >/dev/null 2>&1; then
	DSH_BIN="$(realpath "$(command -v dsh)")"
	DSH_PKG="$(dirname "$(dirname "$DSH_BIN")")"
	DSH_NODE_MODULES="$DSH_PKG/node_modules"
	if [[ ! -d "$DSH_NODE_MODULES/@deepseek-ai" ]]; then
		echo "build.sh: found 'dsh' at $DSH_BIN but no @deepseek-ai under $DSH_NODE_MODULES" >&2
		exit 1
	fi
fi

TSCONFIG_HOST="$ROOT/tsconfig.json"
if [[ -n "${DSH_NODE_MODULES:-}" ]]; then
	# Throwaway config extending the host config with a paths override.
	# `paths` affects only the type checker; emitted module specifiers are
	# untouched, so lib/*.js keeps resolving @deepseek-ai at runtime from
	# node_modules (registry versions provided by `npm install`).
	TSCONFIG_HOST="$ROOT/.tsconfig.dsh.json"
	cat > "$TSCONFIG_HOST" <<EOF
{
  "extends": "./tsconfig.json",
  "compilerOptions": {
    "baseUrl": ".",
    "paths": { "@deepseek-ai/*": ["$DSH_NODE_MODULES/@deepseek-ai/*"] }
  }
}
EOF
	echo "==> type-checking @deepseek-ai against dsh install: $DSH_NODE_MODULES/@deepseek-ai"
	trap 'rm -f "$TSCONFIG_HOST"' EXIT
else
	echo "==> no 'dsh' found: building against registry-pinned @deepseek-ai under node_modules"
	echo "    (type-check result will match that registry snapshot, not necessarily a local harness)."
fi

# ---------------------------------------------------------------------------
# 3. Compile the HOST half: src/ -> lib/ (tsc; src/client is excluded from
#    tsconfig.json — it is a browser bundle, built by tsdown below).
#    lib/ is wiped first so files removed from src/ (e.g. the old ui.ts)
#    never linger in the shipped package.
# ---------------------------------------------------------------------------
rm -rf lib
mkdir -p lib
echo "==> compiling host half with tsc -p $TSCONFIG_HOST ..."
npx tsc -p "$TSCONFIG_HOST"

# ---------------------------------------------------------------------------
# 3b. Compile the CLIENT half type surface: src/client -> lib/types/client
#     (typecheck + declaration emit; the runtime bundle is tsdown's job).
# ---------------------------------------------------------------------------
echo "==> typechecking client half + emitting declarations (tsc -p tsconfig.client.json) ..."
npx tsc -p tsconfig.client.json

# ---------------------------------------------------------------------------
# 3c. Bundle the CLIENT half: src/client/index.tsx -> lib/client.js
#     (CJS closure factory registered via window.__ModuleLoader__.load).
# ---------------------------------------------------------------------------
echo "==> bundling client half with tsdown ..."
npx tsdown

# ---------------------------------------------------------------------------
# 4. Verify the build output.
# ---------------------------------------------------------------------------
if [[ ! -f lib/index.js ]]; then
	echo "build.sh: build failed — lib/index.js was not produced" >&2
	exit 1
fi
if [[ ! -f lib/client.js ]]; then
	echo "build.sh: build failed — lib/client.js was not produced (tsdown step)" >&2
	exit 1
fi
echo "==> build ok: $(find lib -name '*.js' | wc -l) JS files in lib/ (incl. lib/client.js)"

# ---------------------------------------------------------------------------
# 5. Run the unit test suite.
#    (Node >=20 does not accept a bare directory for --test; pass a glob.)
# ---------------------------------------------------------------------------
if [[ "$RUN_TESTS" -eq 1 ]]; then
	echo "==> running unit tests (node --test 'tools/test-*.mjs') ..."
	node --test 'tools/test-*.mjs'
	echo "==> all done: build + tests"
else
	echo "==> all done: build only (--no-test)"
fi