// Package exitcode is a pure knowledge base for process exit codes: the
// POSIX shell conventions (126/127/128+N), BSD sysexits, and the container
// and tooling conventions (125, 137, 143, 255) that generate most of the
// "why did my process exit with code X?" searches. Everything is data —
// no OS access — so explanations are deterministic.
package exitcode

import (
	"fmt"

	"github.com/JaydenCJ/whydied/internal/signals"
)

// Class groups exit codes by which convention they belong to.
type Class string

const (
	ClassSuccess  Class = "success"
	ClassGeneric  Class = "generic-error"
	ClassUsage    Class = "usage-error"
	ClassSysexits Class = "sysexits"
	ClassExec     Class = "exec-failure"
	ClassSignal   Class = "fatal-signal"
	ClassApp      Class = "application-defined"
	ClassRange    Class = "out-of-range"
)

// Explanation decodes one exit code.
type Explanation struct {
	Code    int    `json:"code"`
	Class   Class  `json:"class"`
	Name    string `json:"name,omitempty"` // conventional name, e.g. EX_USAGE
	Summary string `json:"summary"`
	// Detail lists likely causes and caveats, most likely first.
	Detail []string `json:"detail"`
	// Signal is set for 129–192: the signal implied by the 128+N shell
	// convention. The convention is a report, not proof — an application
	// is free to call exit(137) itself, which is why Detail says "usually".
	Signal *signals.Info `json:"signal,omitempty"`
}

// sysexit is one row of the BSD sysexits.h table (still used by mailers,
// argparse-style CLIs, and anything that includes sysexits.h).
type sysexit struct {
	name, summary string
}

var sysexits = map[int]sysexit{
	64: {"EX_USAGE", "command line usage error"},
	65: {"EX_DATAERR", "input data was incorrect in some way"},
	66: {"EX_NOINPUT", "an input file did not exist or was not readable"},
	67: {"EX_NOUSER", "the user specified did not exist"},
	68: {"EX_NOHOST", "the host specified did not exist"},
	69: {"EX_UNAVAILABLE", "a required service or resource is unavailable"},
	70: {"EX_SOFTWARE", "internal software error detected by the program itself"},
	71: {"EX_OSERR", "an operating system error (fork, pipe, …) occurred"},
	72: {"EX_OSFILE", "a system file is missing or has the wrong format"},
	73: {"EX_CANTCREAT", "a user-specified output file cannot be created"},
	74: {"EX_IOERR", "an error occurred while doing I/O on a file"},
	75: {"EX_TEMPFAIL", "temporary failure — retrying later may succeed"},
	76: {"EX_PROTOCOL", "the remote system returned something impossible during a protocol exchange"},
	77: {"EX_NOPERM", "insufficient permission to perform the operation"},
	78: {"EX_CONFIG", "something was found in an unconfigured or misconfigured state"},
}

// Explain decodes an exit code in 0–255. Values outside that range are an
// error: the wait interface only carries eight bits, so anything else was
// already wrapped modulo 256 before you could observe it.
func Explain(code int) (Explanation, error) {
	if code < 0 || code > 255 {
		return Explanation{}, fmt.Errorf(
			"exit code %d is outside 0-255: the kernel truncates exit statuses to 8 bits, so this value can never be observed (%d would appear as %d)",
			code, code, ((code%256)+256)%256)
	}
	e := Explanation{Code: code}
	switch {
	case code == 0:
		e.Class = ClassSuccess
		e.Summary = "success"
		e.Detail = []string{
			"the process exited normally and reported no error",
		}
	case code == 1:
		e.Class = ClassGeneric
		e.Summary = "catch-all failure: the program decided to fail and picked the default code"
		e.Detail = []string{
			"read the program's own stderr — code 1 carries no more information than \"something went wrong\"",
			"some tools give 1 a specific meaning: for grep it is merely \"no lines matched\", not an error",
		}
	case code == 2:
		e.Class = ClassUsage
		e.Summary = "misuse of the command: bad flags or arguments (shell-builtin convention)"
		e.Detail = []string{
			"bash builtins, many GNU tools, and Python's argparse exit 2 on usage errors — recheck the command line",
			"a shell script that ran `exit 2` explicitly, or bash reporting a syntax error in the script itself",
		}
	case sysexitEntry(code, &e):
		// populated by sysexitEntry
	case code == 125:
		e.Class = ClassApp
		e.Summary = "the wrapper failed, not your program (docker/git convention)"
		e.Detail = []string{
			"`docker run` exits 125 when the Docker daemon or the run itself failed before your command started",
			"`git bisect run` treats 125 as \"cannot test this revision, skip it\"",
			"chroot and some other launchers also reserve 125 for their own failures",
		}
	case code == 126:
		e.Class = ClassExec
		e.Summary = "command found but not executable"
		e.Detail = []string{
			"the file exists but lacks the execute bit (`chmod +x`), or points at a directory",
			"in containers: a script whose interpreter exists but refuses to run it (permissions, noexec mount)",
		}
	case code == 127:
		e.Class = ClassExec
		e.Summary = "command not found"
		e.Detail = []string{
			"the executable is not on PATH, or the path is misspelled",
			"in containers: the binary is missing from the image, or a script's #! interpreter does not exist — a script with Windows CRLF line endings makes `/bin/sh\\r` \"not found\"",
			"a dynamically linked binary whose loader (e.g. glibc on an Alpine/musl image) is missing also reports 127",
		}
	case code == 128:
		e.Class = ClassUsage
		e.Summary = "invalid argument to exit"
		e.Detail = []string{
			"a script called `exit` with a non-numeric argument, so the shell substituted 128",
			"exactly 128 is never produced by the 128+N signal convention (there is no signal 0)",
		}
	case code > 128 && code <= 192:
		sig, _ := signals.FromExitCode(code)
		e.Class = ClassSignal
		e.Name = sig.Name
		e.Summary = fmt.Sprintf("usually: killed by %s (128+%d, %s)", sig.Name, sig.Number, sig.Description)
		e.Signal = &sig
		e.Detail = append(e.Detail,
			fmt.Sprintf("shells and most runtimes report \"died of signal %d\" as exit code 128+%d = %d", sig.Number, sig.Number, code))
		e.Detail = append(e.Detail, signalNarrative(sig)...)
		e.Detail = append(e.Detail,
			"caveat: this is a reporting convention, not proof — a program can also call exit("+fmt.Sprint(code)+") itself; `whydied run` observes the real wait status instead")
	case code == 255:
		e.Class = ClassApp
		e.Summary = "exit status out of range, or a tool's own catch-all"
		e.Detail = []string{
			"a program returned -1 (or any negative value) from main or exit(), which wraps to 255",
			"ssh exits 255 for its own connection errors, so `ssh host cmd` giving 255 usually means the connection failed, not cmd",
			"some tools (rsync wrappers, xargs) use 255 as \"fatal, stop everything\"",
		}
	default:
		e.Class = ClassApp
		e.Summary = "application-defined exit code"
		e.Detail = []string{
			"no POSIX or sysexits convention assigns a meaning here — consult the program's documentation",
			"if this came out of a shell as $?, note that values ≥ 256 in the program wrap modulo 256 on the way out",
		}
	}
	return e, nil
}

// sysexitEntry fills e when code is in the BSD sysexits range and reports
// whether it did.
func sysexitEntry(code int, e *Explanation) bool {
	sx, ok := sysexits[code]
	if !ok {
		return false
	}
	e.Class = ClassSysexits
	e.Name = sx.name
	e.Summary = fmt.Sprintf("%s (BSD sysexits): %s", sx.name, sx.summary)
	e.Detail = []string{
		"the sysexits.h convention is honored by sendmail-lineage mailers, many BSD tools, and CLIs that include sysexits",
		"programs that never heard of sysexits can still emit this value with their own meaning — check the tool's docs",
	}
	return true
}

// signalNarrative adds cause bullets for the signal behind a 128+N code,
// leading with the OOM story for SIGKILL because that is, empirically,
// what people hitting exit 137 are looking at.
func signalNarrative(sig signals.Info) []string {
	out := make([]string, 0, len(sig.Causes)+1)
	out = append(out, sig.Causes...)
	if sig.Default == signals.Core {
		out = append(out, "default action dumps core — check for a core file or coredumpctl entry")
	}
	return out
}
