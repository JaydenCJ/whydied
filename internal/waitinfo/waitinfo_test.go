// Tests for wait-status decoding: the raw POSIX status word, the 128+N
// inference from bare exit codes, and the shell-code round trip.
package waitinfo

import (
	"strings"
	"testing"
)

func TestFromExitCodePlain(t *testing.T) {
	d := FromExitCode(3)
	if !d.Exited || d.ExitCode != 3 || d.Signaled || d.Inferred {
		t.Errorf("FromExitCode(3) = %+v", d)
	}
	// There is no signal 0: 128 must stay a plain exit.
	d = FromExitCode(128)
	if d.Signaled || d.Inferred {
		t.Errorf("FromExitCode(128) = %+v, want plain exit", d)
	}
}

func TestFromExitCode137InfersSIGKILL(t *testing.T) {
	d := FromExitCode(137)
	if !d.Signaled || d.Signal != 9 || !d.Inferred {
		t.Errorf("FromExitCode(137) = %+v, want inferred signal 9", d)
	}
	// The original code must survive for reporting.
	if d.ExitCode != 137 {
		t.Errorf("ExitCode = %d, want 137", d.ExitCode)
	}
}

func TestFromRawNormalExit(t *testing.T) {
	// POSIX packs the exit code into bits 8-15.
	d := FromRaw(42 << 8)
	if !d.Exited || d.ExitCode != 42 || d.Signaled {
		t.Errorf("FromRaw(42<<8) = %+v", d)
	}
}

func TestFromRawSignalDeathWithCore(t *testing.T) {
	// SIGSEGV (11) with the core flag (0x80).
	d := FromRaw(11 | 0x80)
	if !d.Signaled || d.Signal != 11 || !d.CoreDumped || d.Inferred {
		t.Errorf("FromRaw(11|0x80) = %+v", d)
	}
	// SIGKILL (9) without core.
	d = FromRaw(9)
	if !d.Signaled || d.Signal != 9 || d.CoreDumped {
		t.Errorf("FromRaw(9) = %+v", d)
	}
	// SignalInfo resolves the table entry; clean exits have none.
	sig, ok := FromRaw(11 | 0x80).SignalInfo()
	if !ok || sig.Name != "SIGSEGV" {
		t.Errorf("SignalInfo = %v %v", sig, ok)
	}
	if _, ok := FromExitCode(0).SignalInfo(); ok {
		t.Error("clean exit has no signal info")
	}
}

func TestFromRawStoppedIsNeither(t *testing.T) {
	// WIFSTOPPED status (low bits 0x7f) is not a death.
	d := FromRaw(19<<8 | 0x7f)
	if d.Exited || d.Signaled {
		t.Errorf("stopped status decoded as death: %+v", d)
	}
	if !strings.Contains(d.Describe(), "stopped") {
		t.Errorf("Describe() = %q", d.Describe())
	}
}

func TestShellCodeRoundTrip(t *testing.T) {
	// A real SIGKILL death reports as 137, exactly what a shell says.
	if got := FromRaw(9).ShellCode(); got != 137 {
		t.Errorf("SIGKILL ShellCode = %d, want 137", got)
	}
	// An inferred death keeps the code it came from.
	if got := FromExitCode(137).ShellCode(); got != 137 {
		t.Errorf("inferred ShellCode = %d, want 137", got)
	}
	if got := FromExitCode(7).ShellCode(); got != 7 {
		t.Errorf("plain ShellCode = %d, want 7", got)
	}
}

func TestDescribeDistinguishesRealFromInferred(t *testing.T) {
	real := FromRaw(9).Describe()
	inferred := FromExitCode(137).Describe()
	if !strings.Contains(real, "killed by SIGKILL") {
		t.Errorf("real death: %q", real)
	}
	if !strings.Contains(inferred, "usually") || !strings.Contains(inferred, "137") {
		t.Errorf("inferred death must hedge and cite the code: %q", inferred)
	}
	if real == inferred {
		t.Error("real and inferred deaths must read differently")
	}
}
