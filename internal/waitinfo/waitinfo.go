// Package waitinfo decodes how a process ended into one small struct,
// from either a raw POSIX wait status (which distinguishes "exited 137"
// from "killed by SIGKILL" with certainty) or a bare exit code (where the
// 128+N convention only lets us infer the signal).
package waitinfo

import (
	"fmt"

	"github.com/JaydenCJ/whydied/internal/signals"
)

// Death records how a process ended.
type Death struct {
	// Exited is true for a normal exit; ExitCode is then meaningful.
	Exited   bool `json:"exited"`
	ExitCode int  `json:"exit_code"`
	// Signaled is true when a signal terminated the process; Signal is
	// the number and CoreDumped whether the kernel wrote a core.
	Signaled   bool `json:"signaled"`
	Signal     int  `json:"signal,omitempty"`
	CoreDumped bool `json:"core_dumped,omitempty"`
	// Inferred marks a signal deduced from a 128+N exit code rather than
	// observed in a wait status: the process may equally have called
	// exit(128+N) itself.
	Inferred bool `json:"inferred,omitempty"`
}

// FromExitCode builds a Death from a bare exit code, applying the 128+N
// convention: 129–192 are recorded as an *inferred* signal death.
func FromExitCode(code int) Death {
	if sig, ok := signals.FromExitCode(code); ok {
		return Death{
			Exited:   true,
			ExitCode: code,
			Signaled: true,
			Signal:   sig.Number,
			Inferred: true,
		}
	}
	return Death{Exited: true, ExitCode: code}
}

// FromRaw decodes a raw POSIX wait status word (the value waitpid(2)
// stores), covering normal exits and signal deaths. A stopped status
// (0x7f low bits) is reported as neither exited nor signaled.
func FromRaw(status uint32) Death {
	const (
		sigMask  = 0x7f
		coreFlag = 0x80
	)
	switch {
	case status&sigMask == 0: // WIFEXITED
		return Death{Exited: true, ExitCode: int(status>>8) & 0xff}
	case status&sigMask == 0x7f: // WIFSTOPPED (or continued 0xffff)
		return Death{}
	default: // WIFSIGNALED
		return Death{
			Signaled:   true,
			Signal:     int(status & sigMask),
			CoreDumped: status&coreFlag != 0,
		}
	}
}

// SignalInfo resolves the signal behind a signaled Death.
func (d Death) SignalInfo() (signals.Info, bool) {
	if !d.Signaled {
		return signals.Info{}, false
	}
	return signals.ByNumber(d.Signal)
}

// ShellCode is the exit code a POSIX shell would report for this death:
// the exit code itself, or 128+signal.
func (d Death) ShellCode() int {
	if d.Signaled && !d.Inferred {
		return 128 + d.Signal
	}
	return d.ExitCode
}

// Describe renders a one-line human summary of the death.
func (d Death) Describe() string {
	switch {
	case d.Signaled && d.Inferred:
		sig, _ := signals.ByNumber(d.Signal)
		return fmt.Sprintf("exit code %d — by the 128+N convention, usually death by %s", d.ExitCode, sig.Name)
	case d.Signaled:
		sig, _ := signals.ByNumber(d.Signal)
		core := ""
		if d.CoreDumped {
			core = ", core dumped"
		}
		return fmt.Sprintf("killed by %s (signal %d%s)", sig.Name, d.Signal, core)
	case d.Exited && d.ExitCode == 0:
		return "exited normally (code 0)"
	case d.Exited:
		return fmt.Sprintf("exited with code %d", d.ExitCode)
	default:
		return "stopped (not dead)"
	}
}
