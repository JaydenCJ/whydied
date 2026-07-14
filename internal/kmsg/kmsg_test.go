// Tests for the kernel-log parser: every message family (OOM kill,
// cgroup OOM, summary line, invocation, segfault, traps) in every
// transport wrapping (dmesg, dmesg -T, /dev/kmsg, journalctl/syslog),
// plus the x86 page-fault error-code decoder.
package kmsg

import (
	"os"
	"strings"
	"testing"
)

func parseOne(t *testing.T, line string) Event {
	t.Helper()
	ev, ok := ParseLine(line)
	if !ok {
		t.Fatalf("line not recognized: %q", line)
	}
	return ev
}

func TestGlobalOOMKillModernFormat(t *testing.T) {
	ev := parseOne(t, "[74233.402170] Out of memory: Killed process 2001 (stress) total-vm:8394204kB, anon-rss:7912448kB, file-rss:1024kB, shmem-rss:0kB, UID:1000 pgtables:15672kB oom_score_adj:0")
	if ev.Kind != KindOOMKill || ev.PID != 2001 || ev.Comm != "stress" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.CgroupConstrained {
		t.Error("global OOM must not be marked cgroup-constrained")
	}
	if ev.TotalVMKB != 8394204 || ev.AnonRSSKB != 7912448 || ev.FileRSSKB != 1024 || ev.ShmemRSSKB != 0 {
		t.Errorf("memory accounting wrong: %+v", ev)
	}
	if ev.UID != 1000 || ev.OOMScoreAdj == nil || *ev.OOMScoreAdj != 0 {
		t.Errorf("uid/adj wrong: uid=%d adj=%v", ev.UID, ev.OOMScoreAdj)
	}
	if ev.Timestamp != "74233.402170" {
		t.Errorf("timestamp = %q", ev.Timestamp)
	}
}

func TestMemoryCgroupOOMKillIsCgroupConstrained(t *testing.T) {
	ev := parseOne(t, "[74108.201549] Memory cgroup out of memory: Killed process 1337 (java) total-vm:7000840kB, anon-rss:519168kB, file-rss:3072kB, shmem-rss:0kB, UID:0 pgtables:1437kB oom_score_adj:979")
	if ev.Kind != KindOOMKill || !ev.CgroupConstrained {
		t.Fatalf("event = %+v", ev)
	}
	if ev.OOMScoreAdj == nil || *ev.OOMScoreAdj != 979 {
		t.Errorf("oom_score_adj = %v, want 979", ev.OOMScoreAdj)
	}
}

func TestLegacyAndSysctlOOMWordings(t *testing.T) {
	// Pre-4.19 kernels log "Kill process" (present tense) with a score;
	// sysctl oom_kill_allocating_task changes the wording again.
	ev := parseOne(t, "[1234.567890] Out of memory: Kill process 9876 (mysqld) score 856 or sacrifice child")
	if ev.Kind != KindOOMKill || ev.PID != 9876 || ev.Comm != "mysqld" {
		t.Fatalf("event = %+v", ev)
	}
	ev = parseOne(t, "[99.000001] Out of memory (oom_kill_allocating_task): Killed process 41 (alloc) total-vm:100kB, anon-rss:50kB, file-rss:0kB, shmem-rss:0kB")
	if ev.Kind != KindOOMKill || ev.PID != 41 {
		t.Fatalf("event = %+v", ev)
	}
}

func TestOOMSummaryLineMemcg(t *testing.T) {
	ev := parseOne(t, "[74108.201541] oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=/,mems_allowed=0,oom_memcg=/kubepods.slice/pod7c1a,task_memcg=/kubepods.slice/pod7c1a/cri-4be2,task=java,pid=1337,uid=0")
	if ev.Kind != KindOOMSummary || !ev.CgroupConstrained {
		t.Fatalf("event = %+v", ev)
	}
	if ev.OOMMemcg != "/kubepods.slice/pod7c1a" || ev.TaskMemcg != "/kubepods.slice/pod7c1a/cri-4be2" {
		t.Errorf("memcg fields: %+v", ev)
	}
	if ev.PID != 1337 || ev.Comm != "java" || ev.UID != 0 {
		t.Errorf("identity fields: %+v", ev)
	}
}

func TestOOMSummaryLineGlobalHasNoOOMMemcg(t *testing.T) {
	ev := parseOne(t, "[74233.402161] oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=/user.slice/session-4.scope,task=stress,pid=2001,uid=1000")
	if ev.Kind != KindOOMSummary || ev.CgroupConstrained {
		t.Fatalf("event = %+v", ev)
	}
	if ev.OOMMemcg != "" || ev.Constraint != "CONSTRAINT_NONE" {
		t.Errorf("constraint fields: %+v", ev)
	}
}

func TestOOMInvokedNamesTheAllocator(t *testing.T) {
	ev := parseOne(t, "[74108.201335] java invoked oom-killer: gfp_mask=0xcc0(GFP_KERNEL), order=0, oom_score_adj=979")
	if ev.Kind != KindOOMInvoked || ev.Comm != "java" {
		t.Fatalf("event = %+v", ev)
	}
	// The invoker has no PID field in this line — it must stay 0 so
	// ForPID never misattributes it.
	if ev.PID != 0 {
		t.Errorf("invoked event PID = %d, want 0", ev.PID)
	}
}

func TestSegfaultLineFullDecode(t *testing.T) {
	ev := parseOne(t, "[74211.870041] myapp[4242]: segfault at 0 ip 0000557a1c2e4f10 sp 00007ffd93c1a2c0 error 4 in myapp[557a1c2b0000+9d000] likely on CPU 5 (core 5, socket 0)")
	if ev.Kind != KindSegfault || ev.PID != 4242 || ev.Comm != "myapp" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Addr != "0" || ev.ErrCode != 4 || ev.Object != "myapp" {
		t.Errorf("fault fields: addr=%q err=%d obj=%q", ev.Addr, ev.ErrCode, ev.Object)
	}
}

func TestSegfaultInSharedLibrary(t *testing.T) {
	ev := parseOne(t, "[100.000001] worker[555]: segfault at 7f31a0000000 ip 00007f31b2e44f10 sp 00007ffc93c1a2c0 error 6 in libcrunch.so.2[7f31b2e30000+178000]")
	if ev.Object != "libcrunch.so.2" || ev.ErrCode != 6 {
		t.Errorf("event = %+v", ev)
	}
}

func TestTrapVariants(t *testing.T) {
	// The three fatal-trap wordings the fault handlers emit: divide
	// error (SIGFPE), general protection fault, and invalid opcode.
	ev := parseOne(t, "[74310.202331] traps: crasher[7707] trap divide error ip:401126 sp:7ffe45b2c860 error:0 in crasher[401000+1000]")
	if ev.Kind != KindTrap || ev.PID != 7707 || ev.TrapName != "divide error" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Object != "crasher" {
		t.Errorf("object = %q", ev.Object)
	}
	ev = parseOne(t, "[74399.118240] traps: pluginhost[8090] general protection fault ip:7f2a81c440b7 sp:7ffc19d02040 error:0 in libplugin.so.1[7f2a81c2f000+2b000]")
	if ev.Kind != KindTrap || ev.TrapName != "general protection fault" {
		t.Fatalf("event = %+v", ev)
	}
	ev = parseOne(t, "[55.000001] traps: newbin[321] trap invalid opcode ip:401000 sp:7ffd00000000 error:0 in newbin[400000+2000]")
	if ev.Kind != KindTrap || ev.TrapName != "invalid opcode" {
		t.Fatalf("event = %+v", ev)
	}
}

func TestDevKmsgWrapping(t *testing.T) {
	// /dev/kmsg: "pri,seq,usec,flags;message" — usec becomes seconds;
	// continuation lines (leading space) carry no message.
	ev := parseOne(t, "6,1201,74310202331,-;traps: crasher[7707] trap divide error ip:401126 sp:7ffe45b2c860 error:0 in crasher[401000+1000]")
	if ev.Kind != KindTrap || ev.Timestamp != "74310.202331" {
		t.Fatalf("event = %+v", ev)
	}
	if _, ok := ParseLine(" SUBSYSTEM=traps"); ok {
		t.Error("continuation lines must not parse as events")
	}
}

func TestSyslogAndISOWrapping(t *testing.T) {
	// journalctl / kern.log wrapping, with and without the inner [ts].
	ev := parseOne(t, "Jul 12 16:09:14 node-a kernel: [74233.402170] Out of memory: Killed process 2001 (stress) total-vm:8394204kB, anon-rss:7912448kB, file-rss:1024kB, shmem-rss:0kB")
	if ev.PID != 2001 || ev.Timestamp != "Jul 12 16:09:14" {
		t.Fatalf("event = %+v", ev)
	}
	ev = parseOne(t, "2026-07-12T16:09:14.123456+00:00 node-a kernel: myapp[77]: segfault at 10 ip 0000557a1c2e4f10 sp 00007ffd93c1a2c0 error 4")
	if ev.Kind != KindSegfault || ev.PID != 77 {
		t.Fatalf("event = %+v", ev)
	}
}

func TestDmesgHumanTimestampWrapping(t *testing.T) {
	// dmesg -T uses a textual timestamp in the same brackets.
	ev := parseOne(t, "[Sun Jul 12 16:09:14 2026] Out of memory: Killed process 8 (a) total-vm:1kB, anon-rss:1kB, file-rss:0kB, shmem-rss:0kB")
	if ev.Kind != KindOOMKill || ev.Timestamp != "Sun Jul 12 16:09:14 2026" {
		t.Fatalf("event = %+v", ev)
	}
}

func TestCRLFAndNoiseLinesSkipped(t *testing.T) {
	ev := parseOne(t, "[1.000000] Out of memory: Killed process 5 (x) total-vm:1kB, anon-rss:1kB, file-rss:0kB, shmem-rss:0kB\r")
	if ev.PID != 5 {
		t.Fatalf("CRLF line not handled: %+v", ev)
	}
	for _, noise := range []string{
		"[12.000000] systemd[1]: Started Journal Service.",
		"[13.000000] eth0: link becomes ready",
		"random text with no structure",
		"",
	} {
		if _, ok := ParseLine(noise); ok {
			t.Errorf("noise parsed as event: %q", noise)
		}
	}
}

func TestParseFixtureFileEndToEnd(t *testing.T) {
	// The shipped example capture: 9 events, in order, across all
	// wrapping formats. This pins the parser against a realistic log.
	f, err := os.Open("../../examples/kern.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 9 {
		t.Fatalf("got %d events, want 9: %+v", len(events), kinds(events))
	}
	want := []Kind{KindOOMInvoked, KindOOMSummary, KindOOMKill, KindSegfault,
		KindOOMInvoked, KindOOMSummary, KindOOMKill, KindTrap, KindTrap}
	for i, k := range want {
		if events[i].Kind != k {
			t.Errorf("event %d = %s, want %s", i, events[i].Kind, k)
		}
	}
}

func TestForPIDFiltersExactly(t *testing.T) {
	f, err := os.Open("../../examples/kern.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, _ := Parse(f)
	got := ForPID(events, 1337)
	if len(got) != 2 { // summary + kill for java
		t.Fatalf("ForPID(1337) = %d events, want 2", len(got))
	}
	for _, ev := range got {
		if ev.PID != 1337 {
			t.Errorf("wrong pid in filtered set: %+v", ev)
		}
	}
	if len(ForPID(events, 99999)) != 0 {
		t.Error("unknown pid should match nothing")
	}
}

func TestDecodeSegfaultErrorBits(t *testing.T) {
	cases := map[int][]string{
		4:    {"user-mode", "read from", "unmapped"},         // NULL deref
		6:    {"user-mode", "write to", "unmapped"},          // write through bad pointer
		7:    {"user-mode", "write to", "protected"},         // write to read-only page
		0x14: {"user-mode", "instruction fetch", "unmapped"}, // jump to bad address (error 14)
		0:    {"kernel-mode", "read from"},
	}
	for code, wants := range cases {
		got := DecodeSegfaultError(code)
		for _, w := range wants {
			if !strings.Contains(got, w) {
				t.Errorf("DecodeSegfaultError(%#x) = %q, missing %q", code, got, w)
			}
		}
	}
}

func kinds(events []Event) []Kind {
	out := make([]Kind, len(events))
	for i, ev := range events {
		out[i] = ev.Kind
	}
	return out
}
