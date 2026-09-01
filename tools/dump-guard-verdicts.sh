#!/usr/bin/env bash
# dump-guard-verdicts.sh — observe the verdict history of agent-security-guard
#
# Reads the plugin's own verdict audit file ($DSH_HOME/agent-security-guard/
# verdicts.jsonl, written by audit.ts) and aggregates pass/deny/ask per session,
# listing the blocked-call details. The plugin intentionally does NOT write
# verdicts into the harness session log (the harness telemetry layer treats a
# committed `feedback/record` as the session-export consent signal — see B1 in
# the open-source readiness review).
#
# Usage:
#   ./dump-guard-verdicts.sh                 # summarize all sessions
#   ./dump-guard-verdicts.sh <keyword>       # only match sessions whose id contains the keyword
#   ./dump-guard-verdicts.sh --detail        # additionally print the details of every verdict
set -euo pipefail

DSH_HOME="${DSH_HOME:-$HOME/.dsh}"
DETAIL=0
FILTER=""

for arg in "$@"; do
  case "$arg" in
    --detail|-d) DETAIL=1 ;;
    --help|-h) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) FILTER="$arg" ;;
  esac
done

LOG_FILE="$DSH_HOME/agent-security-guard/verdicts.jsonl"
if [[ ! -f "$LOG_FILE" ]]; then
  echo "Verdict audit file not found: $LOG_FILE" >&2
  echo "Make sure the plugin is enabled and has produced conversations/tool calls (allow verdicts are not persisted by default)." >&2
  exit 1
fi

python3 - "$LOG_FILE" "$FILTER" "$DETAIL" <<'PY'
import json, sys, os

path, filter_, detail = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
verdicts = []
with open(path, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            verdicts.append(json.loads(line))
        except Exception:
            continue

if filter_:
    verdicts = [v for v in verdicts if filter_ in v.get("sessionId", "")]

if not verdicts:
    print("No verdict records found (allow verdicts are not persisted by default).")
    sys.exit(0)

from collections import defaultdict, Counter
by_session = defaultdict(list)
for v in verdicts:
    by_session[v.get("sessionId", "?")].append(v)

found = False
for session_id, vs in by_session.items():
    counts = Counter(v.get("outcome", "?") for v in vs)
    print(f"===== {session_id} =====")
    print(f"  {len(vs)} verdicts total  "
          + "  ".join(f"{k}={counts.get(k,0)}" for k in ("pass", "deny", "ask")))
    for v in vs:
        if v.get("outcome") != "deny":
            continue
        print(f"  [blocked] turn={v.get('turn','?')} hook={v.get('hook','?')} "
              f"tool={v.get('tool','-')} policy={v.get('policyId','-')} "
              f"msg={v.get('message','')}")
    if detail:
        for v in sorted(vs, key=lambda x: x.get("time", 0)):
            print(f"  seq={v.get('seq','?')} turn={v.get('turn','?')} step={v.get('step','-')} "
                  f"hook={v.get('hook','?')} action={v.get('action','?')} "
                  f"outcome={v.get('outcome','?')} tool={v.get('tool','-')} "
                  f"callId={v.get('callId','-')} policy={v.get('policyId','-')}")
        print()
    found = True

if not found:
    print("No verdict records found.")
PY