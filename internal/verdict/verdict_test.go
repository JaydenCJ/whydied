// Tests for the verdict engine: each evidence tier (kernel OOM record,
// cgroup counter delta, near-limit circumstantial, bare wait status) must
// produce the right cause AND the right confidence — overclaiming is as
// much a bug as missing a diagnosis.
package verdict

import (
	"bytes"
	"strings"
	"testing"

	"github.com/JaydenCJ/whydied/internal/cgroup"
	"github.com/JaydenCJ/whydied/internal/kmsg"
	"github.com/JaydenCJ/whydied/internal/waitinfo"
)

// mustEvents parses kernel-log text for a test scenario.
func mustEvents(t *testing.T, text string) []kmsg.Event {
	t.Helper()
	events, err := kmsg.Parse(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	return events
}

const cgroupOOMLog = `[100.000001] java invoked oom-killer: gfp_mask=0xcc0(GFP_KERNEL), order=0, oom_score_adj=979
[100.000002] oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=/,mems_allowed=0,oom_memcg=/kubepods.slice/pod1,task_memcg=/kubepods.slice/pod1/cri-1,task=java,pid=1337,uid=0
[100.000003] Memory cgroup out of memory: Killed process 1337 (java) total-vm:7000840kB, anon-rss:519168kB, file-rss:3072kB, shmem-rss:0kB, UID:0 pgtables:1437kB oom_score_adj:979
`

func TestCgroupOOMKillIsConfirmedWithMemcgEvidence(t *testing.T) {
	v := Diagnose(Input{
		PID:          1337,
		Events:       mustEvents(t, cgroupOOMLog),
		KmsgSearched: true,
	})
	if v.Cause != CauseOOMCgroup || v.Confidence != Confirmed {
		t.Fatalf("verdict = %s/%s", v.Cause, v.Confidence)
	}
	if v.Comm != "java" || v.PID != 1337 {
		t.Errorf("identity from kernel log not adopted: %s/%d", v.Comm, v.PID)
	}
	if !evidenceContains(v, "/kubepods.slice/pod1") {
		t.Error("verdict must name the cgroup that hit its limit")
	}
	if !evidenceContains(v, "anon-rss") {
		t.Error("verdict must carry the memory accounting")
	}
	if !adviceContains(v, "memory.max") {
		t.Error("cgroup OOM advice should mention raising the limit")
	}
}

func TestGlobalOOMKillIsDistinguishedFromCgroup(t *testing.T) {
	log := `[200.000001] Out of memory: Killed process 2001 (stress) total-vm:8394204kB, anon-rss:7912448kB, file-rss:1024kB, shmem-rss:0kB, UID:1000 pgtables:15672kB oom_score_adj:0`
	v := Diagnose(Input{PID: 2001, Events: mustEvents(t, log), KmsgSearched: true})
	if v.Cause != CauseOOMGlobal || v.Confidence != Confirmed {
		t.Fatalf("verdict = %s/%s", v.Cause, v.Confidence)
	}
	if !strings.Contains(v.Headline, "host ran out of memory") {
		t.Errorf("headline = %q", v.Headline)
	}
	if !adviceContains(v, "oom_score") {
		t.Error("global OOM advice should mention victim-selection controls")
	}
}

func TestOOMEventsForOtherPIDsAreIgnored(t *testing.T) {
	// A kill record for pid 1337 is not evidence about pid 42.
	v := Diagnose(Input{
		PID:          42,
		Death:        &waitinfo.Death{Exited: true, ExitCode: 1},
		Events:       mustEvents(t, cgroupOOMLog),
		KmsgSearched: true,
	})
	if v.Cause == CauseOOMCgroup {
		t.Fatalf("misattributed another process's OOM kill: %+v", v)
	}
}

func TestSegfaultRecordConfirmsWithDecodedFault(t *testing.T) {
	log := `[300.000001] myapp[4242]: segfault at 0 ip 0000557a1c2e4f10 sp 00007ffd93c1a2c0 error 4 in myapp[557a1c2b0000+9d000]`
	v := Diagnose(Input{PID: 4242, Events: mustEvents(t, log), KmsgSearched: true})
	if v.Cause != CauseSegfault || v.Confidence != Confirmed {
		t.Fatalf("verdict = %s/%s", v.Cause, v.Confidence)
	}
	if !evidenceContains(v, "read from an unmapped address") {
		t.Error("verdict must decode the x86 error code")
	}
	if !adviceContains(v, "NULL") {
		t.Error("a fault at address 0 should point at NULL pointers")
	}
}

func TestTrapRecordNamesTheSignal(t *testing.T) {
	log := `[400.000001] traps: crasher[7707] trap divide error ip:401126 sp:7ffe45b2c860 error:0 in crasher[401000+1000]`
	v := Diagnose(Input{PID: 7707, Events: mustEvents(t, log), KmsgSearched: true})
	if v.Cause != CauseTrap || v.Confidence != Confirmed {
		t.Fatalf("verdict = %s/%s", v.Cause, v.Confidence)
	}
	if !strings.Contains(v.Headline, "SIGFPE") {
		t.Errorf("divide error should map to SIGFPE: %q", v.Headline)
	}
}

func TestCgroupCounterDeltaConfirmsWithoutKernelLog(t *testing.T) {
	before := cgroup.Snapshot{Version: 2, Path: "/sys/fs/cgroup/box", OOMKills: 3, MaxBytes: 1 << 29}
	after := cgroup.Snapshot{Version: 2, Path: "/sys/fs/cgroup/box", OOMKills: 4, MaxBytes: 1 << 29, PeakBytes: 1 << 29}
	v := Diagnose(Input{
		Death:        &waitinfo.Death{Signaled: true, Signal: 9},
		Comm:         "worker",
		PID:          88,
		Cgroup:       &after,
		CgroupBefore: &before,
	})
	if v.Cause != CauseOOMCgroup || v.Confidence != Confirmed {
		t.Fatalf("verdict = %s/%s", v.Cause, v.Confidence)
	}
	if !evidenceContains(v, "oom_kill went 3 -> 4") {
		t.Error("delta evidence missing")
	}
	// And the counterexample: an unchanged counter must not fire.
	snap := cgroup.Snapshot{Version: 2, OOMKills: 3}
	v = Diagnose(Input{
		Death:        &waitinfo.Death{Exited: true, ExitCode: 1},
		Cgroup:       &snap,
		CgroupBefore: &snap,
	})
	if v.Cause == CauseOOMCgroup {
		t.Fatalf("no delta, but OOM verdict: %+v", v)
	}
}

func TestSIGKILLNearLimitIsLikelyOOMNotConfirmed(t *testing.T) {
	// Circumstantial tier: SIGKILL + cgroup pinned at its limit, but no
	// kernel record. Must say "likely", never "confirmed".
	snap := cgroup.Snapshot{Version: 2, Path: "/box", MaxBytes: 1000, PeakBytes: 1000}
	v := Diagnose(Input{
		Death:  &waitinfo.Death{Signaled: true, Signal: 9},
		Comm:   "hog",
		Cgroup: &snap,
	})
	if v.Cause != CauseOOMCgroup || v.Confidence != Likely {
		t.Fatalf("verdict = %s/%s, want oom-kill-cgroup/likely", v.Cause, v.Confidence)
	}
	if !adviceContains(v, "whydied scan") {
		t.Error("should tell the user how to get kernel-log confirmation")
	}
}

func TestSIGKILLWithSearchedLogAndNoRecordPointsOutside(t *testing.T) {
	v := Diagnose(Input{
		Death:        &waitinfo.Death{Signaled: true, Signal: 9},
		Comm:         "svc",
		PID:          10,
		KmsgSearched: true,
	})
	if v.Cause != CauseSignal || v.Confidence != Likely {
		t.Fatalf("verdict = %s/%s", v.Cause, v.Confidence)
	}
	if !strings.Contains(v.Headline, "outside the kernel") {
		t.Errorf("headline = %q", v.Headline)
	}
}

func TestSIGKILLWithoutAnyLogStaysPossible(t *testing.T) {
	// With no kernel log at all, both hypotheses stay open and the
	// confidence must drop to "possible".
	v := Diagnose(Input{Death: &waitinfo.Death{Signaled: true, Signal: 9}, Comm: "svc"})
	if v.Confidence != Possible {
		t.Fatalf("confidence = %s, want possible", v.Confidence)
	}
	if !strings.Contains(v.Headline, "OOM killer") || !strings.Contains(v.Headline, "external kill") {
		t.Errorf("headline must keep both hypotheses open: %q", v.Headline)
	}
}

func TestSIGTERMExplainsOrchestrators(t *testing.T) {
	v := Diagnose(Input{Death: &waitinfo.Death{Signaled: true, Signal: 15}, Comm: "api"})
	if v.Cause != CauseSignal {
		t.Fatalf("cause = %s", v.Cause)
	}
	if !adviceContains(v, "Kubernetes") && !adviceContains(v, "systemd") {
		t.Error("SIGTERM advice should mention orchestrated shutdowns")
	}
}

func TestInferredSignalCarriesTheCaveat(t *testing.T) {
	// Exit code 137 without a wait status: the verdict must flag the
	// inference and the exit(137) alternative.
	v := Diagnose(Input{Death: ptr(waitinfo.FromExitCode(137)), Comm: "job"})
	if v.Cause != CauseOOMCgroup && v.Cause != CauseSignalInferred {
		t.Fatalf("cause = %s", v.Cause)
	}
	if !evidenceContains(v, "128+N") && !evidenceContains(v, "128+9") {
		t.Errorf("inference caveat missing: %+v", v.Evidence)
	}
}

func TestCleanExitAndPlainCodes(t *testing.T) {
	v := Diagnose(Input{Death: &waitinfo.Death{Exited: true, ExitCode: 0}, Comm: "ok"})
	if v.Cause != CauseCleanExit || v.Confidence != Info {
		t.Fatalf("clean exit verdict = %s/%s", v.Cause, v.Confidence)
	}
	v = Diagnose(Input{Death: &waitinfo.Death{Exited: true, ExitCode: 127}, Comm: "runner"})
	if v.Cause != CauseExitCode || !strings.Contains(v.Headline, "not found") {
		t.Fatalf("127 verdict = %+v", v)
	}
}

func TestCoreDumpEvidenceForSegvWithoutKernelLog(t *testing.T) {
	v := Diagnose(Input{Death: &waitinfo.Death{Signaled: true, Signal: 11, CoreDumped: true}, Comm: "app"})
	if !evidenceContains(v, "core dump") {
		t.Error("a dumped core is evidence and should be surfaced")
	}
}

func TestUnknownVerdictWhenNothingMatches(t *testing.T) {
	v := Diagnose(Input{PID: 4711, KmsgSearched: true})
	if v.Cause != CauseUnknown || v.Confidence != Possible {
		t.Fatalf("verdict = %s/%s", v.Cause, v.Confidence)
	}
	if !evidenceContains(v, "no OOM-kill") {
		t.Error("a searched-but-empty log is itself evidence and should be recorded")
	}
}

func TestRenderCompleteAndDeterministic(t *testing.T) {
	in := Input{PID: 1337, Events: mustEvents(t, cgroupOOMLog), KmsgSearched: true}
	var buf bytes.Buffer
	Render(Diagnose(in), &buf)
	out := buf.String()
	for _, want := range []string{"verdict:", "cause: oom-kill-cgroup", "confidence: confirmed", "evidence:", "[kernel log]", "advice:"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered report missing %q:\n%s", want, out)
		}
	}
	var again bytes.Buffer
	Render(Diagnose(in), &again)
	if again.String() != out {
		t.Error("identical input must render byte-identical output")
	}
}

func evidenceContains(v Verdict, sub string) bool {
	for _, e := range v.Evidence {
		if strings.Contains(e.Detail, sub) {
			return true
		}
	}
	return false
}

func adviceContains(v Verdict, sub string) bool {
	for _, a := range v.Advice {
		if strings.Contains(a, sub) {
			return true
		}
	}
	return false
}

func ptr[T any](v T) *T { return &v }
