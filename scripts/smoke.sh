#!/usr/bin/env bash
# End-to-end smoke test for whydied: builds the binary, then exercises
# every subcommand against real child processes and the shipped kernel-log
# fixture, asserting on real output and exit codes. No network,
# idempotent, finishes in seconds.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
  echo "SMOKE FAIL: $*" >&2
  exit 1
}

BIN="$WORKDIR/whydied"
FIXTURE="$ROOT/examples/kern.log"

echo "1. build"
(cd "$ROOT" && go build -o "$BIN" ./cmd/whydied) || fail "go build failed"

echo "2. version matches manifest"
"$BIN" --version | grep -qx "whydied 0.1.0" || fail "--version mismatch"

echo "3. the flagship shortcut: whydied 137"
OUT="$("$BIN" 137)"
echo "$OUT" | grep -q "SIGKILL" || fail "137 did not decode to SIGKILL"
echo "$OUT" | grep -q "OOM killer" || fail "137 did not mention the OOM killer"

echo "4. exit-code knowledge base"
"$BIN" code 127 | grep -q "command not found" || fail "127 explanation wrong"
"$BIN" code 69 | grep -q "EX_UNAVAILABLE" || fail "sysexits row missing"

echo "5. signal knowledge base"
OUT="$("$BIN" signal SIGSEGV)"
echo "$OUT" | grep -q "core dump" || fail "SIGSEGV should mention core dumps"
echo "$OUT" | grep -q "exit code 139" || fail "128+N shell code missing"

echo "6. scan the fixture kernel log"
OUT="$("$BIN" scan --kmsg "$FIXTURE")"
echo "$OUT" | grep -q "whydied scan: 9 events, 5 process deaths" || fail "scan counts wrong"
echo "$OUT" | grep -q "oom-kill    pid=1337 comm=java" || fail "cgroup OOM kill not listed"
echo "$OUT" | grep -q "constraint=host-oom" || fail "global OOM kill not listed"

echo "7. pid post-mortem: confirmed cgroup OOM with evidence"
OUT="$("$BIN" pid 1337 --kmsg "$FIXTURE")"
echo "$OUT" | grep -q "cause: oom-kill-cgroup   confidence: confirmed" || fail "OOM verdict wrong"
echo "$OUT" | grep -q "kubepods.slice" || fail "memcg path missing from evidence"

echo "8. pid post-mortem: segfault with decoded fault"
"$BIN" pid 4242 --kmsg "$FIXTURE" | grep -q "segmentation fault" || fail "segfault verdict missing"

echo "9. JSON envelope is stable"
JSON="$("$BIN" pid 1337 --kmsg "$FIXTURE" --json)"
echo "$JSON" | grep -q '"tool": "whydied"' || fail "json envelope missing"
echo "$JSON" | grep -q '"schema_version": 1' || fail "schema_version missing"
echo "$JSON" | grep -q '"cause": "oom-kill-cgroup"' || fail "json cause wrong"

echo "10. run: passthrough of a plain exit code"
set +e
"$BIN" run -- sh -c 'exit 42' 2>"$WORKDIR/report.txt"
[ $? -eq 42 ] || fail "run should pass exit 42 through"
set -e
grep -q "exited with code 42" "$WORKDIR/report.txt" || fail "run diagnosis missing"

echo "11. run: a real SIGKILL death observed via wait status"
set +e
"$BIN" run -- sh -c 'kill -KILL $$' 2>"$WORKDIR/report.txt"
[ $? -eq 137 ] || fail "run should report SIGKILL as 137"
set -e
grep -q "killed by SIGKILL" "$WORKDIR/report.txt" || fail "SIGKILL diagnosis missing"

echo "12. run: clean exits stay silent and child stdout passes through"
OUT="$("$BIN" run -- sh -c 'echo payload' 2>"$WORKDIR/report.txt")"
[ "$OUT" = "payload" ] || fail "child stdout not passed through"
[ -s "$WORKDIR/report.txt" ] && fail "clean exit must not produce a report"

echo "13. usage errors exit 2"
set +e
"$BIN" code 300 >/dev/null 2>&1
[ $? -eq 2 ] || fail "out-of-range code should exit 2"
"$BIN" frobnicate >/dev/null 2>&1
[ $? -eq 2 ] || fail "unknown command should exit 2"
set -e

echo "SMOKE OK"
