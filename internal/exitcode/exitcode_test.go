// Tests for the exit-code knowledge base: every convention tier (POSIX
// shell, sysexits, container tooling, 128+N) plus the range guard rails.
package exitcode

import (
	"strings"
	"testing"
)

func explain(t *testing.T, code int) Explanation {
	t.Helper()
	e, err := Explain(code)
	if err != nil {
		t.Fatalf("Explain(%d): %v", code, err)
	}
	return e
}

func TestZeroIsSuccess(t *testing.T) {
	e := explain(t, 0)
	if e.Class != ClassSuccess || e.Signal != nil {
		t.Errorf("Explain(0) = class %s, signal %v", e.Class, e.Signal)
	}
}

func TestLowCodesClassified(t *testing.T) {
	// Code 1 must warn that it is a catch-all AND that some tools (grep)
	// use it benignly — both halves prevent misdiagnosis. Code 2 is the
	// shell-builtin/argparse usage convention.
	e := explain(t, 1)
	if e.Class != ClassGeneric {
		t.Fatalf("class = %s", e.Class)
	}
	if !containsAny(e.Detail, "grep") {
		t.Error("code 1 explanation should mention the grep no-match convention")
	}
	if e := explain(t, 2); e.Class != ClassUsage {
		t.Errorf("code 2 class = %s, want %s", e.Class, ClassUsage)
	}
}

func TestSysexitsRangeFullyMapped(t *testing.T) {
	// All 15 sysexits.h codes (64-78) carry their EX_ name.
	wantNames := map[int]string{64: "EX_USAGE", 69: "EX_UNAVAILABLE", 70: "EX_SOFTWARE",
		75: "EX_TEMPFAIL", 77: "EX_NOPERM", 78: "EX_CONFIG"}
	for code := 64; code <= 78; code++ {
		e := explain(t, code)
		if e.Class != ClassSysexits || !strings.HasPrefix(e.Name, "EX_") {
			t.Errorf("Explain(%d) = class %s name %q", code, e.Class, e.Name)
		}
	}
	for code, name := range wantNames {
		if e := explain(t, code); e.Name != name {
			t.Errorf("Explain(%d).Name = %q, want %q", code, e.Name, name)
		}
	}
}

func Test125IsWrapperFailure(t *testing.T) {
	e := explain(t, 125)
	if !containsAny(e.Detail, "docker") || !containsAny(e.Detail, "bisect") {
		t.Errorf("code 125 should cite the docker and git bisect conventions, got %v", e.Detail)
	}
}

func Test126NotExecutable127NotFound(t *testing.T) {
	if e := explain(t, 126); e.Class != ClassExec || !strings.Contains(e.Summary, "not executable") {
		t.Errorf("126 = %q", e.Summary)
	}
	e := explain(t, 127)
	if e.Class != ClassExec || !strings.Contains(e.Summary, "not found") {
		t.Errorf("127 = %q", e.Summary)
	}
	// The CRLF shebang trap generates a huge share of container 127s.
	if !containsAny(e.Detail, "CRLF") {
		t.Error("127 should warn about CRLF shebang lines")
	}
}

func Test128IsNotASignal(t *testing.T) {
	// Off-by-one guard: 128 = invalid exit argument, NOT signal 0.
	e := explain(t, 128)
	if e.Signal != nil || e.Class == ClassSignal {
		t.Errorf("128 must not decode as a signal death: %+v", e)
	}
}

func Test137DecodesToSIGKILLWithOOMFirst(t *testing.T) {
	e := explain(t, 137)
	if e.Class != ClassSignal || e.Signal == nil || e.Signal.Name != "SIGKILL" {
		t.Fatalf("137 = %+v", e)
	}
	if !containsAny(e.Detail, "OOM") {
		t.Error("137 must lead the reader to the OOM killer")
	}
	if !containsAny(e.Detail, "convention, not proof") {
		t.Error("137 must carry the exit(137)-is-possible caveat")
	}
}

func Test139And143DecodeWithCorrectCoreNotes(t *testing.T) {
	// Both decode to their signals; only the core-dumping one (SIGSEGV)
	// may promise a core file.
	e := explain(t, 139)
	if e.Signal == nil || e.Signal.Name != "SIGSEGV" {
		t.Errorf("139 signal = %v", e.Signal)
	}
	if !containsAny(e.Detail, "core") {
		t.Error("139 (SIGSEGV) should mention core dumps")
	}
	e = explain(t, 143)
	if e.Signal == nil || e.Signal.Name != "SIGTERM" {
		t.Errorf("143 signal = %v", e.Signal)
	}
	if containsAny(e.Detail, "core file") {
		t.Error("143 (SIGTERM) should not promise a core dump")
	}
}

func Test255AndPlainAppCodesAreHonest(t *testing.T) {
	e := explain(t, 255)
	if !containsAny(e.Detail, "-1") || !containsAny(e.Detail, "ssh") {
		t.Errorf("255 detail = %v", e.Detail)
	}
	// 42 has no convention; the tool must say so rather than invent one.
	e = explain(t, 42)
	if e.Class != ClassApp || e.Signal != nil {
		t.Errorf("42 = class %s signal %v", e.Class, e.Signal)
	}
}

func TestOutOfRangeCodesAreRejectedWithWrapHint(t *testing.T) {
	for _, code := range []int{-1, 256, 512} {
		if _, err := Explain(code); err == nil {
			t.Errorf("Explain(%d) should fail", code)
		}
	}
	// The error must teach the modulo-256 wrap: 256 would appear as 0.
	_, err := Explain(256)
	if err == nil || !strings.Contains(err.Error(), "8 bits") {
		t.Errorf("range error should explain 8-bit truncation: %v", err)
	}
}

func TestEverySignalCodeInRangeResolves(t *testing.T) {
	// 129-192 all decode without panicking, including RT signals.
	for code := 129; code <= 192; code++ {
		e := explain(t, code)
		if e.Class != ClassSignal || e.Signal == nil {
			t.Errorf("Explain(%d) = class %s, signal %v", code, e.Class, e.Signal)
		}
	}
}

// containsAny reports whether any detail line contains the substring
// (case-sensitive; call sites pick unambiguous tokens).
func containsAny(details []string, sub string) bool {
	for _, d := range details {
		if strings.Contains(d, sub) {
			return true
		}
	}
	return false
}
