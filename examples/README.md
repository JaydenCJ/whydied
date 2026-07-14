# whydied examples

Two runnable scripts and one fixture, all offline and self-contained:

- **`kern.log`** — a realistic kernel-log capture mixing every wrapping
  format whydied parses (dmesg, `/dev/kmsg`, journalctl/syslog): a
  Kubernetes cgroup OOM kill, a host-wide OOM kill, a segfault, a divide
  error, and a general protection fault. Use it to try `scan` and `pid`
  without needing a machine that just OOMed.

- **`postmortem.sh`** — walks the fixture through the post-mortem views:
  the `scan` overview, confirmed per-PID verdicts with their evidence,
  and the `--json` envelope for scripting.

- **`wrap-entrypoint.sh`** — the supervision pattern: `whydied run` as a
  transparent wrapper around real child processes. Clean exits stay
  silent, deaths get a diagnosis on stderr, and the child's exit code
  passes through untouched.

Both scripts build the binary from source on first use (any Go ≥1.22)
and never touch the network.

```bash
bash examples/postmortem.sh
bash examples/wrap-entrypoint.sh
```
