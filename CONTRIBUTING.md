# Contributing to whydied

Issues, discussions and pull requests are all welcome.

## Getting started

You need Go ≥1.22; nothing else — the tool and its tests are pure
standard library and never touch the network.

```bash
git clone https://github.com/JaydenCJ/whydied && cd whydied
go build ./...
go test ./...
bash scripts/smoke.sh
```

`scripts/smoke.sh` builds the binary, then exercises every subcommand
against real child processes and the shipped kernel-log fixture —
verdicts, JSON envelopes, exit-code passthrough, usage errors; it must
finish by printing `SMOKE OK`.

## Before you open a pull request

1. `gofmt -l .` reports nothing (formatting is enforced).
2. `go vet ./...` passes with no findings.
3. `go test ./...` passes (93 deterministic tests, no network).
4. `bash scripts/smoke.sh` prints `SMOKE OK`.
5. Add tests for behavior changes; keep logic in pure, unit-testable
   modules (the knowledge bases, the kmsg parser, and the verdict engine
   never touch the OS — only the CLI and the cgroup reader do).

## Ground rules

- Keep dependencies at zero; adding one needs strong justification in
  the PR.
- No network calls, ever, and no telemetry — whydied only reads the
  kernel log and cgroup files you point it at.
- Never overclaim: a verdict's confidence must match its evidence. A new
  diagnosis rule needs a test for the case where it must NOT fire.
- New kernel-log formats need a verbatim sample line in the test (and in
  `examples/kern.log` if the family is new), with a comment citing which
  kernel emits it.
- Code comments and doc comments are written in English.
- Determinism first: identical input must produce byte-identical output —
  reports get pasted into issues and compared.

## Reporting bugs

Include the output of `whydied version`, the full command you ran, and —
for parser bugs — the exact kernel-log line that was misread (scrub
hostnames if needed; the message part after `kernel:` is what matters).
For wrong verdicts, `--json` output plus the raw evidence is the perfect
repro.

## Security

Please do not open public issues for security problems; use GitHub's
private vulnerability reporting on this repository instead.
