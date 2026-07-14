#!/usr/bin/env bash
# Demonstrate `whydied run` as a transparent wrapper: stdout and exit
# codes pass through untouched, and the diagnosis lands on stderr only
# when something actually dies. This is the pattern for container
# ENTRYPOINTs, CI steps, and cron jobs. Offline; uses tiny sh children
# that die in deterministic ways.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/whydied"

[ -x "$BIN" ] || (cd "$ROOT" && go build -o "$BIN" ./cmd/whydied)

echo "== clean exit: whydied stays completely silent =="
"$BIN" run -- sh -c 'echo "work done"'
echo "(exit $?)"

echo
echo "== app error: exit code diagnosed, then passed through =="
"$BIN" run -- sh -c 'echo "loading config"; exit 78' || echo "(exit $?)"

echo
echo "== signal death: the wait status names the real signal =="
"$BIN" run -- sh -c 'kill -TERM $$' || echo "(exit $?)"
