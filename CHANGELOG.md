# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- Exit-code knowledge base (`code`, and the bare `whydied 137` shortcut):
  POSIX shell conventions (126/127/128+N), all 15 BSD sysexits, container
  and tooling conventions (125, 255), and the explicit caveat that 128+N
  is a report, not proof.
- Signal knowledge base (`signal`): all classic Linux signals 1–31 with
  default actions, core-dump behavior, catchability, and typical causes;
  real-time signals (SIGRTMIN±n) and glibc-reserved 32/33.
- Kernel-log parser (`scan`): OOM kills (global and cgroup-constrained,
  modern and pre-4.19 wordings), `oom-kill:constraint=` summary lines
  with memcg paths, oom-killer invocations, segfaults with x86 error-code
  decoding, and fatal traps (divide error, invalid opcode, general
  protection fault) — read from dmesg output, `/dev/kmsg`, journalctl,
  or syslog files (`--kmsg`, with `-` for stdin).
- cgroup evidence reader: v2 `memory.events`/`memory.max`/`memory.peak`
  and v1 `memory.oom_control`/`limit_in_bytes` layouts, with sentinel
  handling for files older kernels lack.
- Verdict engine (`pid`): combines wait status, kernel records, and
  cgroup counters into one diagnosis with an explicit confidence tier
  (confirmed / likely / possible / info), sourced evidence lines, and
  actionable advice — and never overclaims.
- Supervisor (`run`): wraps any command transparently (stdio and exit
  code pass through, 128+N for signal deaths), observes the real wait
  status and rusage peak RSS, diffs the cgroup `oom_kill` counter across
  the run, and searches the kernel log on abnormal death.
- `--json` output behind a stable `schema_version: 1` envelope on every
  command.
- Runnable examples (`examples/postmortem.sh`,
  `examples/wrap-entrypoint.sh`, `examples/kern.log`) and an evidence
  reference (`docs/evidence.md`).
- 93 deterministic offline tests (pure-module units plus in-process CLI
  integration with real child processes) and `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/whydied/releases/tag/v0.1.0
