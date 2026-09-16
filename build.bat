@echo off
rem ===========================================================================
rem build.bat - build lib/ from src/ for the deepseek-harness-security-guard
rem plugin. Windows (cmd.exe) port of build.sh.
rem
rem Dependencies: Node.js 22+ and npm on PATH. A plain `npm install` provides
rem the dev toolchain (typescript, tsdown, @types/react, @types/node) and the
rem type/type-scope @deepseek-ai/* packages declared in package.json.
rem
rem Version alignment with the RUNNING dsh harness (see build.sh for details):
rem   When a `dsh` installation exists, @deepseek-ai/* imports are type-checked
rem   against the dsh install's own node_modules via a generated throwaway
rem   tsconfig `paths` override (.tsconfig.dsh.json, deleted when the script
rem   exits). The alignment is TYPE-CHECK-ONLY: node_modules is never mutated
rem   (no symlinks, no copies - npm install reify follows symlinks and would
rem   wipe the dsh install's own @deepseek-ai packages). Without a local dsh
rem   the build falls back to the registry-pinned @deepseek-ai packages and
rem   logs a warning.
rem
rem Usage:
rem   build.bat            build lib/ and run tests
rem   build.bat --no-test  build lib/ only, skip tests
rem   set DSH_NODE_MODULES=C:\path\to\dsh\node_modules   override dsh detection
rem ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"

set "TSCONFIG_DSH="

rem ---------------------------------------------------------------------------
rem 0. Parse arguments: --no-test / --test.
rem ---------------------------------------------------------------------------
set "RUN_TESTS=1"
:parse_args
if "%~1"=="" goto args_done
if /i "%~1"=="--no-test" (
    set "RUN_TESTS=0"
) else if /i "%~1"=="--test" (
    set "RUN_TESTS=1"
) else (
    echo build.bat: unknown argument: %~1 1>&2
    exit /b 2
)
shift
goto parse_args
:args_done

rem ---------------------------------------------------------------------------
rem 1. Ensure the toolchain is installed.
rem ---------------------------------------------------------------------------
where npx >nul 2>&1
if errorlevel 1 (
    echo build.bat: 'npx' not found - install Node.js 22+ for Windows and add it to PATH 1>&2
    exit /b 1
)
if exist "node_modules\.bin\tsc.cmd" if exist "node_modules\.bin\tsdown.cmd" goto toolchain_ok
echo build.bat: missing tsc/tsdown - run "npm install" first [Node 22+, npm] 1>&2
exit /b 1
:toolchain_ok

rem ---------------------------------------------------------------------------
rem 2. Align @deepseek-ai/* types with the running dsh installation.
rem    Type-only alignment via a generated tsconfig `paths` override.
rem    node_modules is never mutated (see header). Without a local dsh the
rem    plain tsconfig.json is used (registry-pinned types from node_modules).
rem ---------------------------------------------------------------------------
set "TSCONFIG_HOST=tsconfig.json"
if defined DSH_NODE_MODULES goto dsh_env

where dsh >nul 2>&1
if errorlevel 1 goto no_dsh
set "DSH_SHIM="
for /f "delims=" %%F in ('where dsh 2^>nul') do if not defined DSH_SHIM set "DSH_SHIM=%%F"
for %%I in ("%DSH_SHIM%") do set "SHIM_DIR=%%~dpI"
rem npm global layout: the shim dir has a sibling node_modules
if exist "%SHIM_DIR%node_modules\@deepseek-ai\" set "DSH_NODE_MODULES=%SHIM_DIR%node_modules"
if defined DSH_NODE_MODULES goto dsh_found
rem npm local layout: <root>\node_modules\.bin\<shim> - node_modules is the grandparent
set "SHIM_BASE=%SHIM_DIR:~0,-1%"
for %%I in ("%SHIM_BASE%") do set "PARENT_DIR=%%~dpI"
if exist "%PARENT_DIR%node_modules\@deepseek-ai\" set "DSH_NODE_MODULES=%PARENT_DIR%node_modules"
if defined DSH_NODE_MODULES goto dsh_found
echo build.bat: found 'dsh' at %DSH_SHIM% but no @deepseek-ai packages next to it 1>&2
echo build.bat: set DSH_NODE_MODULES=^<path to dsh node_modules^> and retry 1>&2
exit /b 1

:dsh_env
if exist "%DSH_NODE_MODULES%\@deepseek-ai\" goto dsh_found
echo build.bat: cannot find @deepseek-ai packages under: 1>&2
echo   %DSH_NODE_MODULES% 1>&2
exit /b 1

:dsh_found
rem Forward slashes: tsc accepts them on Windows and they need no JSON escaping.
set "DSH_FWD=%DSH_NODE_MODULES%"
set "DSH_FWD=%DSH_FWD:\=/%"
set "TSCONFIG_HOST=.tsconfig.dsh.json"
set "TSCONFIG_DSH=.tsconfig.dsh.json"
> "%TSCONFIG_DSH%" (
    echo {
    echo   "extends": "./tsconfig.json",
    echo   "compilerOptions": {
    echo     "baseUrl": ".",
    echo     "paths": { "@deepseek-ai/*": ["%DSH_FWD%/@deepseek-ai/*"] }
    echo   }
    echo }
)
echo ==^> type-checking @deepseek-ai against dsh install: %DSH_NODE_MODULES%\@deepseek-ai
goto compile

:no_dsh
echo ==^> no 'dsh' found: building against registry-pinned @deepseek-ai under node_modules
echo     (type-check result will match that registry snapshot, not necessarily a local harness^).

rem ---------------------------------------------------------------------------
rem 3. Compile the HOST half: src/ -> lib/ (tsc; src/client is excluded from
rem    tsconfig.json - it is a browser bundle, built by tsdown below).
rem    lib/ is wiped first so files removed from src/ never linger in the
rem    shipped package.
rem ---------------------------------------------------------------------------
:compile
if exist lib\ rd /s /q lib
mkdir lib
echo ==^> compiling host half with tsc -p %TSCONFIG_HOST% ...
call npx tsc -p "%TSCONFIG_HOST%"
if errorlevel 1 goto build_failed

rem ---------------------------------------------------------------------------
rem 3b. Compile the CLIENT half type surface: src/client -> lib/types/client
rem     (typecheck + declaration emit; the runtime bundle is tsdown's job).
rem ---------------------------------------------------------------------------
echo ==^> typechecking client half + emitting declarations (tsc -p tsconfig.client.json^) ...
call npx tsc -p tsconfig.client.json
if errorlevel 1 goto build_failed

rem ---------------------------------------------------------------------------
rem 3c. Bundle the CLIENT half: src/client/index.tsx -> lib/client.js
rem     (CJS closure factory registered via window.__ModuleLoader__.load).
rem ---------------------------------------------------------------------------
echo ==^> bundling client half with tsdown ...
call npx tsdown
if errorlevel 1 goto build_failed

rem ---------------------------------------------------------------------------
rem 4. Verify the build output.
rem ---------------------------------------------------------------------------
if not exist "lib\index.js" (
    echo build.bat: build failed - lib\index.js was not produced 1>&2
    goto cleanup_fail
)
if not exist "lib\client.js" (
    echo build.bat: build failed - lib\client.js was not produced [tsdown step] 1>&2
    goto cleanup_fail
)
set "JSCOUNT=0"
for /r lib %%F in (*.js) do set /a JSCOUNT+=1
echo ==^> build ok: %JSCOUNT% JS files in lib/ (incl. lib/client.js^)

rem ---------------------------------------------------------------------------
rem 5. Run the unit test suite.
rem    (Node expands the glob itself; Node 21+ accepts globs in --test.)
rem ---------------------------------------------------------------------------
if "%RUN_TESTS%"=="0" (
    echo ==^> all done: build only --no-test
    goto cleanup_ok
)
echo ==^> running unit tests [node --test "tools/test-*.mjs"] ...
node --test "tools/test-*.mjs"
if errorlevel 1 goto tests_failed
echo ==^> all done: build + tests
goto cleanup_ok

:build_failed
echo build.bat: build step failed 1>&2
goto cleanup_fail
:tests_failed
echo build.bat: unit tests failed 1>&2
goto cleanup_fail
:cleanup_fail
call :cleanup
exit /b 1
:cleanup_ok
call :cleanup
exit /b 0

:cleanup
if defined TSCONFIG_DSH if exist "%TSCONFIG_DSH%" del /q "%TSCONFIG_DSH%"
goto :eof
