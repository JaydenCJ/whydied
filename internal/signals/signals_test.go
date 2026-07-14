// Tests for the signal knowledge base: table integrity, tolerant name
// parsing, real-time signals, and the 128+N exit-code mapping — the data
// every verdict is built on.
package signals

import (
	"strings"
	"testing"
)

func TestTableCoversAllClassicSignals(t *testing.T) {
	// Every classic Linux signal 1-31 must have an entry: a gap would
	// make some deaths unexplainable.
	for n := 1; n <= 31; n++ {
		s, ok := ByNumber(n)
		if !ok {
			t.Fatalf("no entry for signal %d", n)
		}
		if s.Number != n {
			t.Errorf("signal %d: entry claims number %d", n, s.Number)
		}
		if !strings.HasPrefix(s.Name, "SIG") {
			t.Errorf("signal %d: name %q lacks SIG prefix", n, s.Name)
		}
		if len(s.Causes) == 0 {
			t.Errorf("signal %d (%s): no typical causes documented", n, s.Name)
		}
	}
}

func TestWellKnownNumbersMatchLinux(t *testing.T) {
	// Pin the numbering that exit-code decoding depends on (x86-64).
	want := map[int]string{
		1: "SIGHUP", 2: "SIGINT", 6: "SIGABRT", 9: "SIGKILL",
		11: "SIGSEGV", 13: "SIGPIPE", 15: "SIGTERM", 19: "SIGSTOP",
		24: "SIGXCPU", 31: "SIGSYS",
	}
	for n, name := range want {
		s, _ := ByNumber(n)
		if s.Name != name {
			t.Errorf("signal %d = %s, want %s", n, s.Name, name)
		}
	}
}

func TestOnlyKillAndStopAreUncatchable(t *testing.T) {
	for n := 1; n <= 31; n++ {
		s, _ := ByNumber(n)
		wantCatchable := n != 9 && n != 19
		if s.Catchable != wantCatchable {
			t.Errorf("%s: catchable=%v, want %v", s.Name, s.Catchable, wantCatchable)
		}
	}
}

func TestCoreDumpingSignalsMatchSignal7(t *testing.T) {
	// The core-dump set drives "check for a core file" advice; keep it
	// aligned with signal(7).
	core := map[int]bool{3: true, 4: true, 5: true, 6: true, 7: true,
		8: true, 11: true, 24: true, 25: true, 31: true}
	for n := 1; n <= 31; n++ {
		s, _ := ByNumber(n)
		if got := s.Default == Core; got != core[n] {
			t.Errorf("%s: core dump=%v, want %v", s.Name, got, core[n])
		}
	}
}

func TestParseAcceptsNumbersAndNames(t *testing.T) {
	for _, token := range []string{"9", "KILL", "kill", "SIGKILL", "sigkill", " SIGKILL "} {
		s, err := Parse(token)
		if err != nil {
			t.Fatalf("Parse(%q): %v", token, err)
		}
		if s.Number != 9 {
			t.Errorf("Parse(%q) = signal %d, want 9", token, s.Number)
		}
	}
}

func TestParseRejectsInvalidTokens(t *testing.T) {
	// Unknown names, near-misses, and out-of-range numbers all fail.
	for _, token := range []string{"", "SIGBOGUS", "kil", "9.5", "0", "-1", "65", "999"} {
		if _, err := Parse(token); err == nil {
			t.Errorf("Parse(%q) should fail", token)
		}
	}
}

func TestRealtimeAndReservedSignals(t *testing.T) {
	// 34-64 synthesize SIGRTMIN+n; 32-33 are glibc-reserved; 65 is past
	// SIGRTMAX and must not exist.
	s, ok := ByNumber(34)
	if !ok || s.Name != "SIGRTMIN" || !s.Realtime {
		t.Fatalf("signal 34 = %+v, want SIGRTMIN realtime", s)
	}
	s, ok = ByNumber(42)
	if !ok || s.Name != "SIGRTMIN+8" {
		t.Fatalf("signal 42 = %q, want SIGRTMIN+8", s.Name)
	}
	if _, ok := ByNumber(65); ok {
		t.Error("signal 65 should not exist")
	}
	if s, err := Parse("SIGRTMIN+3"); err != nil || s.Number != 37 {
		t.Errorf("SIGRTMIN+3 = %d (%v), want 37", s.Number, err)
	}
	if _, err := Parse("SIGRTMIN+40"); err == nil {
		t.Error("SIGRTMIN+40 is past SIGRTMAX and should fail")
	}
	if s, ok := ByNumber(32); !ok || !strings.Contains(s.Description, "glibc") {
		t.Errorf("signal 32 should be explained as glibc-reserved, got %+v", s)
	}
}

func TestFromExitCodeMapsShellConvention(t *testing.T) {
	cases := map[int]string{137: "SIGKILL", 139: "SIGSEGV", 143: "SIGTERM", 134: "SIGABRT", 129: "SIGHUP"}
	for code, name := range cases {
		s, ok := FromExitCode(code)
		if !ok || s.Name != name {
			t.Errorf("FromExitCode(%d) = %q, want %s", code, s.Name, name)
		}
	}
}

func TestFromExitCodeRejectsNonSignalCodes(t *testing.T) {
	// 128 itself has no signal (there is no signal 0); low codes and the
	// far range are not signal deaths either.
	for _, code := range []int{0, 1, 127, 128, 193, 255} {
		if _, ok := FromExitCode(code); ok {
			t.Errorf("FromExitCode(%d) should not resolve to a signal", code)
		}
	}
}

func TestFatalClassification(t *testing.T) {
	kill, _ := ByNumber(9)
	chld, _ := ByNumber(17)
	stop, _ := ByNumber(19)
	if !kill.Fatal() {
		t.Error("SIGKILL must be fatal")
	}
	if chld.Fatal() {
		t.Error("SIGCHLD default is ignore, not fatal")
	}
	if stop.Fatal() {
		t.Error("SIGSTOP stops, it does not kill")
	}
}
