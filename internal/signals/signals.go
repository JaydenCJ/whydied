// Package signals is a pure, offline knowledge base for POSIX signals as
// numbered on Linux (x86-64/arm64 numbering): names, default dispositions,
// core-dump behavior, and the causes each signal typically points at.
// It never touches the OS — everything here is data, so verdicts built on
// it are deterministic and testable.
package signals

import (
	"fmt"
	"strconv"
	"strings"
)

// Disposition is what the kernel does with a signal when the process has
// not installed a handler.
type Disposition string

// Default dispositions, per signal(7).
const (
	Term   Disposition = "terminate"
	Core   Disposition = "terminate (core dump)"
	Ignore Disposition = "ignore"
	Stop   Disposition = "stop"
	Cont   Disposition = "continue"
)

// Info describes one signal: identity, default behavior, and the causes a
// post-mortem should consider first.
type Info struct {
	Number      int         `json:"number"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Default     Disposition `json:"default_action"`
	// KernelSent is true for fault signals the kernel itself raises in
	// response to program behavior (SIGSEGV, SIGFPE, …) — for these,
	// "who sent it" is almost always "your own code".
	KernelSent bool `json:"kernel_sent"`
	// Catchable is false only for SIGKILL and SIGSTOP; an uncatchable
	// terminating signal means the process had no chance to clean up.
	Catchable bool     `json:"catchable"`
	Causes    []string `json:"typical_causes"`
	Realtime  bool     `json:"realtime,omitempty"`
}

// table covers signals 1–31 with Linux x86-64 numbering. Descriptions are
// aligned with signal(7); causes encode the folklore this tool replaces.
var table = []Info{
	{1, "SIGHUP", "hangup on controlling terminal, or daemon reload convention", Term, false, true, []string{
		"the terminal or SSH session that started the process closed",
		"a service manager sent HUP as a reload request and no handler was installed",
	}, false},
	{2, "SIGINT", "keyboard interrupt (Ctrl-C)", Term, false, true, []string{
		"someone pressed Ctrl-C in the foreground terminal",
		"a wrapper or CI runner forwarded an interrupt to the process group",
	}, false},
	{3, "SIGQUIT", "keyboard quit (Ctrl-\\)", Core, false, true, []string{
		"someone pressed Ctrl-\\ to get a core dump",
		"a JVM-style runtime was asked for a thread dump and the default action fired instead",
	}, false},
	{4, "SIGILL", "illegal instruction", Core, true, true, []string{
		"the binary was built for a newer CPU (e.g. AVX-512 on a host without it)",
		"a corrupted binary, bad JIT output, or a jump through a garbage function pointer",
	}, false},
	{5, "SIGTRAP", "trace/breakpoint trap", Core, true, true, []string{
		"a breakpoint fired with no debugger attached",
		"runtime sanitizers or __builtin_trap() reporting a fatal condition",
	}, false},
	{6, "SIGABRT", "abort() called", Core, true, true, []string{
		"a failed assert(), an unhandled C++ exception, or Go/libc runtime abort",
		"glibc heap corruption checks (\"double free or corruption\")",
	}, false},
	{7, "SIGBUS", "bus error: misaligned or invalid physical access", Core, true, true, []string{
		"an mmap-ed file was truncated while a mapping was still being read (common with shared volumes)",
		"misaligned access on strict-alignment hardware",
	}, false},
	{8, "SIGFPE", "fatal arithmetic error", Core, true, true, []string{
		"integer division by zero (despite the name, it is usually integer, not floating point)",
		"INT_MIN / -1 style signed overflow in a division",
	}, false},
	{9, "SIGKILL", "unconditional kill: cannot be caught or ignored", Term, false, false, []string{
		"the kernel OOM killer (check the kernel log — this is the #1 cause on servers)",
		"an explicit `kill -9`, or a container runtime enforcing a memory/timeout limit",
		"systemd SendSIGKILL after a stop timeout expired",
	}, false},
	{10, "SIGUSR1", "user-defined signal 1", Term, false, true, []string{
		"an operator or script sent USR1 expecting a handler (log rotation, stats dump) that was not installed",
	}, false},
	{11, "SIGSEGV", "segmentation fault: invalid memory reference", Core, true, true, []string{
		"NULL or dangling pointer dereference, use-after-free, buffer overflow",
		"stack overflow from unbounded recursion (the guard page faults)",
	}, false},
	{12, "SIGUSR2", "user-defined signal 2", Term, false, true, []string{
		"an operator or script sent USR2 expecting a handler that was not installed",
	}, false},
	{13, "SIGPIPE", "write to a pipe or socket with no reader", Term, false, true, []string{
		"the downstream process in a pipeline exited first (`prog | head` is the classic)",
		"a peer closed a socket and the process kept writing without handling EPIPE",
	}, false},
	{14, "SIGALRM", "alarm() timer expired", Term, false, true, []string{
		"an alarm()/setitimer() deadline fired with no handler — often a homegrown timeout",
	}, false},
	{15, "SIGTERM", "polite termination request", Term, false, true, []string{
		"systemd, Docker, or Kubernetes asked the process to stop (the standard shutdown path)",
		"a plain `kill <pid>`, or a CI job being cancelled",
	}, false},
	{16, "SIGSTKFLT", "stack fault on coprocessor (unused)", Term, false, true, []string{
		"effectively never kernel-generated — someone sent signal 16 explicitly",
	}, false},
	{17, "SIGCHLD", "child stopped or terminated", Ignore, false, true, []string{
		"informational by default; a process does not die from SIGCHLD unless it installed odd handling",
	}, false},
	{18, "SIGCONT", "continue if stopped", Cont, false, true, []string{
		"resumes a stopped process; not a cause of death",
	}, false},
	{19, "SIGSTOP", "unconditional stop: cannot be caught or ignored", Stop, false, false, []string{
		"the process was suspended (not dead) — look for a debugger, cgroup freezer, or `kill -STOP`",
	}, false},
	{20, "SIGTSTP", "terminal stop (Ctrl-Z)", Stop, false, true, []string{
		"someone pressed Ctrl-Z; the process is suspended, not dead",
	}, false},
	{21, "SIGTTIN", "background process tried to read from the terminal", Stop, false, true, []string{
		"a daemonized or backgrounded process still reads stdin — it is stopped, not dead",
	}, false},
	{22, "SIGTTOU", "background process tried to write to the terminal", Stop, false, true, []string{
		"a backgrounded process wrote to a terminal configured with TOSTOP",
	}, false},
	{23, "SIGURG", "urgent data on a socket", Ignore, false, true, []string{
		"informational by default; not a cause of death",
	}, false},
	{24, "SIGXCPU", "CPU time limit exceeded (RLIMIT_CPU)", Core, true, true, []string{
		"the process hit `ulimit -t` / RLIMIT_CPU — check limits set by the shell, systemd, or a batch scheduler",
	}, false},
	{25, "SIGXFSZ", "file size limit exceeded (RLIMIT_FSIZE)", Core, true, true, []string{
		"the process tried to grow a file past `ulimit -f` / RLIMIT_FSIZE",
	}, false},
	{26, "SIGVTALRM", "virtual timer expired", Term, false, true, []string{
		"a setitimer(ITIMER_VIRTUAL) deadline fired with no handler",
	}, false},
	{27, "SIGPROF", "profiling timer expired", Term, false, true, []string{
		"a profiler's ITIMER_PROF fired after its handler was uninstalled or in a fresh exec'd child",
	}, false},
	{28, "SIGWINCH", "window resize", Ignore, false, true, []string{
		"informational by default; not a cause of death",
	}, false},
	{29, "SIGIO", "I/O now possible (async I/O)", Term, false, true, []string{
		"O_ASYNC was enabled on a descriptor but no SIGIO handler was installed",
	}, false},
	{30, "SIGPWR", "power failure notice", Term, false, true, []string{
		"a UPS daemon or hypervisor signalled imminent power loss",
	}, false},
	{31, "SIGSYS", "bad system call", Core, true, true, []string{
		"a seccomp filter killed the process for calling a forbidden syscall (very common in containers and sandboxes)",
		"an actually invalid syscall number, e.g. running a too-new binary on an old kernel",
	}, false},
}

// byNumber and byName are built once from table for O(1) lookups.
var (
	byNumber = func() map[int]Info {
		m := make(map[int]Info, len(table))
		for _, s := range table {
			m[s.Number] = s
		}
		return m
	}()
	byName = func() map[string]Info {
		m := make(map[string]Info, len(table))
		for _, s := range table {
			m[strings.TrimPrefix(s.Name, "SIG")] = s
		}
		return m
	}()
)

// Linux real-time signal range. 32 and 33 are reserved by glibc for
// threading, so SIGRTMIN as seen by programs is 34.
const (
	rtMin = 34
	rtMax = 64
)

// ByNumber returns the Info for a signal number. Real-time signals
// (34–64) get a synthesized entry; 32–33 are reported as glibc-reserved.
func ByNumber(n int) (Info, bool) {
	if s, ok := byNumber[n]; ok {
		return s, true
	}
	if n == 32 || n == 33 {
		return Info{
			Number:      n,
			Name:        fmt.Sprintf("signal %d", n),
			Description: "reserved by glibc for internal thread management",
			Default:     Term,
			Catchable:   true,
			Causes:      []string{"almost never seen from the outside; something sent a raw reserved signal number"},
			Realtime:    true,
		}, true
	}
	if n >= rtMin && n <= rtMax {
		name := "SIGRTMIN"
		if off := n - rtMin; off > 0 {
			name = fmt.Sprintf("SIGRTMIN+%d", off)
		}
		return Info{
			Number:      n,
			Name:        name,
			Description: "POSIX real-time signal (application-defined meaning)",
			Default:     Term,
			Catchable:   true,
			Causes: []string{
				"an application-level protocol (timers, IPC) sent a real-time signal with no handler installed",
			},
			Realtime: true,
		}, true
	}
	return Info{}, false
}

// Parse resolves a user-supplied signal token: a number ("9"), a name with
// or without the SIG prefix ("kill", "SIGKILL"), case-insensitively, and
// SIGRTMIN+n forms.
func Parse(token string) (Info, error) {
	t := strings.TrimSpace(token)
	if t == "" {
		return Info{}, fmt.Errorf("empty signal")
	}
	if n, err := strconv.Atoi(t); err == nil {
		if s, ok := ByNumber(n); ok {
			return s, nil
		}
		return Info{}, fmt.Errorf("no such signal number: %d (valid: 1-31 and 34-64)", n)
	}
	up := strings.ToUpper(t)
	if strings.HasPrefix(up, "SIGRTMIN") {
		off := 0
		if rest := strings.TrimPrefix(up, "SIGRTMIN"); rest != "" {
			n, err := strconv.Atoi(strings.TrimPrefix(rest, "+"))
			if err != nil || n < 0 {
				return Info{}, fmt.Errorf("bad real-time signal: %s", token)
			}
			off = n
		}
		if s, ok := ByNumber(rtMin + off); ok {
			return s, nil
		}
		return Info{}, fmt.Errorf("real-time signal out of range: %s", token)
	}
	up = strings.TrimPrefix(up, "SIG")
	if s, ok := byName[up]; ok {
		return s, nil
	}
	return Info{}, fmt.Errorf("unknown signal: %s", token)
}

// FromExitCode maps the shell convention 128+N back to a signal: a child
// that died of signal N is reported by shells (and most runtimes) as exit
// code 128+N, so 137 → SIGKILL, 139 → SIGSEGV.
func FromExitCode(code int) (Info, bool) {
	if code <= 128 || code > 128+rtMax {
		return Info{}, false
	}
	return ByNumber(code - 128)
}

// Fatal reports whether the signal's default action kills the process
// (with or without a core dump).
func (s Info) Fatal() bool {
	return s.Default == Term || s.Default == Core
}
