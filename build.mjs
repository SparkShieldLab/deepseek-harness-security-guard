#!/usr/bin/env node
// Cross-platform build launcher: build.sh on Linux/macOS, build.bat on
// Windows. The npm lifecycle scripts (build/test/prepare/prepublishOnly)
// call this so a plain `npm install` works on every platform - without it
// the `bash build.sh` prepare step would fail on Windows machines that have
// no usable bash.
import { spawnSync } from "node:child_process";
import process from "node:process";

const onWindows = process.platform === "win32";
const args = process.argv.slice(2);
const res = onWindows
	? spawnSync("cmd.exe", ["/d", "/s", "/c", "build.bat", ...args], { stdio: "inherit" })
	: spawnSync("bash", ["build.sh", ...args], { stdio: "inherit" });
if (res.error) {
	console.error(`build: failed to launch ${onWindows ? "build.bat" : "build.sh"}: ${res.error.message}`);
	process.exit(1);
}
process.exit(res.status ?? 1);
