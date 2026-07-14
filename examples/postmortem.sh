#!/usr/bin/env bash
# Walk the shipped kernel-log capture (kern.log) through every
# post-mortem view: the scan overview, per-PID verdicts, and the JSON
# envelope. Offline and self-contained; builds the binary on first use.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT}/whydied"
FIXTURE="${ROOT}/examples/kern.log"

[ -x "$BIN" ] || (cd "$ROOT" && go build -o "$BIN" ./cmd/whydied)

echo "== every death in the capture =="
"$BIN" scan --kmsg "$FIXTURE"

echo
echo "== verdict: the Kubernetes java container (pid 1337) =="
"$BIN" pid 1337 --kmsg "$FIXTURE"

echo
echo "== verdict: the segfaulting app (pid 4242) =="
"$BIN" pid 4242 --kmsg "$FIXTURE"

echo
echo "== the same verdict, machine-readable =="
"$BIN" pid 1337 --kmsg "$FIXTURE" --json
