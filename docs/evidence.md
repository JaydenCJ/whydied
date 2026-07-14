# Evidence reference

What whydied reads, how it reads it, and what each artifact proves. This
is the folklore the tool encodes, written down once.

## Kernel-log records

The parser (`internal/kmsg`) recognizes five message families, in any of
the wrappings below. Everything else in the log is skipped.

| Kind | Kernel message | What it proves |
|---|---|---|
| `oom-kill` | `Out of memory: Killed process <pid> (<comm>) total-vm:…kB, anon-rss:…kB, …` | the kernel killed this exact process for memory; the kB fields are its memory accounting at kill time |
| `oom-kill` (cgroup) | `Memory cgroup out of memory: Killed process …` | same, but a cgroup limit was hit — the host was not necessarily out of memory |
| `oom-summary` | `oom-kill:constraint=CONSTRAINT_MEMCG,…,oom_memcg=<cg>,task_memcg=<cg>,task=<comm>,pid=<pid>,uid=<uid>` | names the cgroup whose limit was hit vs. the victim's cgroup (kernel ≥4.19) |
| `oom-invoked` | `<comm> invoked oom-killer: gfp_mask=…` | which allocation triggered the hunt — the invoker is often **not** the victim |
| `segfault` | `<comm>[<pid>]: segfault at <addr> ip <ip> sp <sp> error <e> in <object>[…]` | the process crashed itself; the error code decodes the access (below) |
| `trap` | `traps: <comm>[<pid>] trap divide error / invalid opcode / general protection fault ip:… sp:… error:…` | a CPU fault: SIGFPE, SIGILL, or SIGSEGV respectively |

Legacy wordings (`Out of memory: Kill process … score … or sacrifice
child`, pre-4.19) and the `oom_kill_allocating_task` sysctl variant are
also matched.

### Accepted wrappings

| Source | Line shape |
|---|---|
| `dmesg` | `[74108.201549] <message>` (also `dmesg -T` textual timestamps, `<6>` priority tags) |
| `/dev/kmsg` | `6,703,74108201549,-;<message>` (continuation lines starting with a space are skipped) |
| `journalctl -k` / `kern.log` | `Jul 12 16:09:14 host kernel: <message>` or ISO-8601 timestamps; a nested `[ts]` is stripped too |

### Segfault error-code bits (x86)

The `error <e>` value is printed by the kernel in hex. Bits:

| Bit | Meaning when set |
|---|---|
| 0x1 | protection violation (page was mapped); clear = page not present |
| 0x2 | write access; clear = read |
| 0x4 | user mode; clear = kernel mode |
| 0x8 | reserved page-table bit set (corruption) |
| 0x10 | instruction fetch |

So the folklore values: `error 4` = user-mode read of an unmapped address
(the classic NULL dereference), `error 6` = user-mode write to an
unmapped address, `error 7` = write to a mapped but read-only page,
`error 14`/`15` = jump through a bad function pointer.

## cgroup counters

`--cgroup <dir>` (and `run`'s automatic before/after snapshots) read the
memory controller directly:

| File | Hierarchy | Meaning |
|---|---|---|
| `memory.events` → `oom_kill` | v2 | processes the kernel has killed in this cgroup — the hard counter `run` diffs |
| `memory.events` → `oom`, `oom_group_kill` | v2 | limit-hit events; whole-group kills (kernel ≥5.17) |
| `memory.max`, `memory.peak`, `memory.current` | v2 | configured limit (`max` = none), high-water mark (kernel ≥5.19), current usage |
| `memory.oom_control` → `oom_kill` | v1 | kill counter (kernel ≥4.13) |
| `memory.limit_in_bytes`, `memory.max_usage_in_bytes`, `memory.failcnt` | v1 | limit (LLONG_MAX-ish = none), peak, allocation failures |

## Confidence tiers

The verdict engine never overclaims. From strongest to weakest:

1. **confirmed** — a kernel-log record names the PID, or the cgroup
   `oom_kill` counter advanced across a supervised run.
2. **likely** — the death signature plus circumstantial evidence agree
   (e.g. SIGKILL while the cgroup peak sits at the limit), or a searched
   log rules the OOM killer out.
3. **possible** — consistent hypotheses remain; the report says exactly
   what evidence would settle it.
4. **info** — clean exits and plain exit codes: nothing to investigate,
   only conventions to explain.

A bare exit code can never be "confirmed": `137` is a *report* of
SIGKILL, not proof — any program can call `exit(137)`. Only a wait
status, a kernel record, or a cgroup counter upgrades the verdict.
