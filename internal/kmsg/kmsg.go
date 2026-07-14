// Package kmsg parses kernel log output — dmesg (with or without
// timestamps), /dev/kmsg records, journalctl -k lines, and syslog
// kern.log files — into structured death evidence: OOM kills (global and
// cgroup-constrained), oom-killer invocations, segfaults, and fatal traps.
// The parser is pure (io.Reader in, events out) so every format quirk is
// unit-testable offline.
package kmsg

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Kind classifies a kernel-log event.
type Kind string

const (
	// KindOOMKill: "Out of memory: Killed process …" or
	// "Memory cgroup out of memory: Killed process …".
	KindOOMKill Kind = "oom-kill"
	// KindOOMSummary: the "oom-kill:constraint=…" line that accompanies a
	// kill on modern kernels and names the cgroup that hit its limit.
	KindOOMSummary Kind = "oom-summary"
	// KindOOMInvoked: "<comm> invoked oom-killer: …" — names the
	// allocation that triggered the hunt, not necessarily the victim.
	KindOOMInvoked Kind = "oom-invoked"
	// KindSegfault: "<comm>[pid]: segfault at …".
	KindSegfault Kind = "segfault"
	// KindTrap: "traps: <comm>[pid] trap divide error …" and friends,
	// including general protection faults.
	KindTrap Kind = "trap"
)

// Event is one structured kernel-log record about a process death.
type Event struct {
	Kind      Kind   `json:"kind"`
	Timestamp string `json:"timestamp,omitempty"` // raw token from the log, if any
	PID       int    `json:"pid,omitempty"`
	Comm      string `json:"comm,omitempty"`
	Message   string `json:"message"` // prefix-stripped kernel message

	// OOM fields.
	CgroupConstrained bool   `json:"cgroup_constrained,omitempty"` // memcg limit, not host exhaustion
	Constraint        string `json:"constraint,omitempty"`         // CONSTRAINT_MEMCG, CONSTRAINT_NONE, …
	OOMMemcg          string `json:"oom_memcg,omitempty"`          // cgroup whose limit was hit
	TaskMemcg         string `json:"task_memcg,omitempty"`         // cgroup of the killed task
	TotalVMKB         int64  `json:"total_vm_kb,omitempty"`
	AnonRSSKB         int64  `json:"anon_rss_kb,omitempty"`
	FileRSSKB         int64  `json:"file_rss_kb,omitempty"`
	ShmemRSSKB        int64  `json:"shmem_rss_kb,omitempty"`
	UID               int    `json:"uid,omitempty"`
	OOMScoreAdj       *int   `json:"oom_score_adj,omitempty"`

	// Fault fields.
	Addr     string `json:"addr,omitempty"`
	IP       string `json:"ip,omitempty"`
	SP       string `json:"sp,omitempty"`
	ErrCode  int    `json:"err_code,omitempty"`
	Object   string `json:"object,omitempty"` // binary/library the fault hit in
	TrapName string `json:"trap_name,omitempty"`
}

// Prefix strippers, tried in order. Kernel-log lines reach users through
// many pipelines; each wraps the same message differently.
var (
	// /dev/kmsg record: "6,703,4213540234,-;Out of memory: …".
	devKmsgRe = regexp.MustCompile(`^\d+,\d+,(\d+),[^;]*;(.*)$`)
	// journalctl/syslog: "Jul 12 16:09:01 host kernel: …" or
	// "2026-07-12T16:09:01.123456+00:00 host kernel: …".
	syslogRe = regexp.MustCompile(`^((?:[A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d)|(?:\d{4}-\d\d-\d\dT\S+)) \S+ kernel: (.*)$`)
	// dmesg: "[12345.678901] …" or dmesg -T "[Sun Jul 12 16:09:01 2026] …",
	// optionally preceded by a <priority> tag.
	dmesgRe = regexp.MustCompile(`^(?:<\d+>)?\[ *([^\]]+)\] (.*)$`)
)

// Message regexes. These match the formats emitted by mm/oom_kill.c and
// the x86 fault handlers across modern kernels, including the pre-4.19
// two-step "Kill process … / Killed process …" wording.
var (
	oomKillRe = regexp.MustCompile(
		`^(Memory cgroup out of memory|Out of memory(?: \(oom_kill_allocating_task\))?): Kill(?:ed)? process (\d+) \(([^)]*)\)(.*)$`)
	oomSummaryRe = regexp.MustCompile(
		`^oom-kill:constraint=([A-Z_]+),(?:.*oom_memcg=([^,]+))?.*task_memcg=([^,]+),task=(.+),pid=(\d+),uid=(\d+)$`)
	oomInvokedRe = regexp.MustCompile(
		`^(.+) invoked oom-killer: gfp_mask=`)
	segfaultRe = regexp.MustCompile(
		`^(.+)\[(\d+)\]: segfault at ([0-9a-fA-Fx]+) ip ([0-9a-f]+) sp ([0-9a-f]+) error ([0-9a-f]+)(?: in ([^\[ ]+)\[[^\]]*\])?`)
	trapRe = regexp.MustCompile(
		`^traps: (.+)\[(\d+)\] (general protection fault|trap [a-z_ ]+?) ip:([0-9a-f]+) sp:([0-9a-f]+) error:([0-9a-f]+)(?: in ([^\[ ]+)\[[^\]]*\])?`)

	kvKB  = regexp.MustCompile(`([a-z-]+):(\d+)kB`)
	kvUID = regexp.MustCompile(`UID:(\d+)`)
	kvAdj = regexp.MustCompile(`oom_score_adj:(-?\d+)`)
)

// Parse reads kernel-log text and returns every recognized death event in
// order. Unrecognized lines (the vast majority of any real log) are
// skipped silently; scanning never fails on content, only on I/O.
func Parse(r io.Reader) ([]Event, error) {
	var events []Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if ev, ok := ParseLine(sc.Text()); ok {
			events = append(events, ev)
		}
	}
	if err := sc.Err(); err != nil {
		return events, fmt.Errorf("reading kernel log: %w", err)
	}
	return events, nil
}

// ParseLine parses a single kernel-log line in any supported wrapping and
// reports whether it carried a death event.
func ParseLine(line string) (Event, bool) {
	line = strings.TrimRight(line, "\r\n")
	// /dev/kmsg continuation lines (" SUBSYSTEM=…") carry no message.
	if strings.HasPrefix(line, " ") {
		return Event{}, false
	}
	msg, ts := stripPrefix(line)
	ev, ok := parseMessage(msg)
	if !ok {
		return Event{}, false
	}
	ev.Timestamp = ts
	return ev, true
}

// stripPrefix removes transport wrapping and returns the bare kernel
// message plus whatever timestamp token the wrapping carried.
func stripPrefix(line string) (msg, ts string) {
	msg = line
	if m := devKmsgRe.FindStringSubmatch(msg); m != nil {
		// The third field is microseconds since boot; render like dmesg.
		if us, err := strconv.ParseInt(m[1], 10, 64); err == nil {
			ts = fmt.Sprintf("%d.%06d", us/1e6, us%1e6)
		}
		msg = m[2]
	} else if m := syslogRe.FindStringSubmatch(msg); m != nil {
		ts = m[1]
		msg = m[2]
	}
	// A dmesg-style "[ts]" may remain (journald preserves it on some
	// distros), so strip it after the transport prefix.
	if m := dmesgRe.FindStringSubmatch(msg); m != nil {
		if ts == "" {
			ts = strings.TrimSpace(m[1])
		}
		msg = m[2]
	}
	return msg, ts
}

// parseMessage classifies a bare kernel message.
func parseMessage(msg string) (Event, bool) {
	if m := oomKillRe.FindStringSubmatch(msg); m != nil {
		pid, _ := strconv.Atoi(m[2])
		ev := Event{
			Kind:              KindOOMKill,
			Message:           msg,
			PID:               pid,
			Comm:              m[3],
			CgroupConstrained: strings.HasPrefix(m[1], "Memory cgroup"),
		}
		parseOOMDetails(m[4], &ev)
		return ev, true
	}
	if m := oomSummaryRe.FindStringSubmatch(msg); m != nil {
		pid, _ := strconv.Atoi(m[5])
		uid, _ := strconv.Atoi(m[6])
		return Event{
			Kind:              KindOOMSummary,
			Message:           msg,
			Constraint:        m[1],
			OOMMemcg:          m[2],
			TaskMemcg:         m[3],
			Comm:              m[4],
			PID:               pid,
			UID:               uid,
			CgroupConstrained: strings.HasPrefix(m[1], "CONSTRAINT_MEMCG"),
		}, true
	}
	if m := oomInvokedRe.FindStringSubmatch(msg); m != nil {
		return Event{Kind: KindOOMInvoked, Message: msg, Comm: m[1]}, true
	}
	if m := segfaultRe.FindStringSubmatch(msg); m != nil {
		pid, _ := strconv.Atoi(m[2])
		// The kernel prints the page-fault error code with %x.
		errCode64, _ := strconv.ParseInt(m[6], 16, 32)
		errCode := int(errCode64)
		return Event{
			Kind:    KindSegfault,
			Message: msg,
			Comm:    m[1],
			PID:     pid,
			Addr:    m[3],
			IP:      m[4],
			SP:      m[5],
			ErrCode: errCode,
			Object:  m[7],
		}, true
	}
	if m := trapRe.FindStringSubmatch(msg); m != nil {
		pid, _ := strconv.Atoi(m[2])
		errCode64, _ := strconv.ParseInt(m[6], 16, 32)
		errCode := int(errCode64)
		return Event{
			Kind:     KindTrap,
			Message:  msg,
			Comm:     m[1],
			PID:      pid,
			TrapName: strings.TrimSpace(strings.TrimPrefix(m[3], "trap")),
			IP:       m[4],
			SP:       m[5],
			ErrCode:  errCode,
			Object:   m[7],
		}, true
	}
	return Event{}, false
}

// parseOOMDetails extracts the memory accounting from the tail of a
// "Killed process" line: total-vm, anon-rss, file-rss, shmem-rss, UID,
// oom_score_adj. Older kernels omit some fields; absence is fine.
func parseOOMDetails(tail string, ev *Event) {
	for _, m := range kvKB.FindAllStringSubmatch(tail, -1) {
		n, err := strconv.ParseInt(m[2], 10, 64)
		if err != nil {
			continue
		}
		switch m[1] {
		case "total-vm":
			ev.TotalVMKB = n
		case "anon-rss":
			ev.AnonRSSKB = n
		case "file-rss":
			ev.FileRSSKB = n
		case "shmem-rss":
			ev.ShmemRSSKB = n
		}
	}
	if m := kvUID.FindStringSubmatch(tail); m != nil {
		ev.UID, _ = strconv.Atoi(m[1])
	}
	if m := kvAdj.FindStringSubmatch(tail); m != nil {
		adj, err := strconv.Atoi(m[1])
		if err == nil {
			ev.OOMScoreAdj = &adj
		}
	}
}

// ForPID filters events down to those about one PID. OOM-invoked events
// carry no PID and are excluded — the invoker is often not the victim.
func ForPID(events []Event, pid int) []Event {
	var out []Event
	for _, ev := range events {
		if ev.PID == pid && ev.PID != 0 {
			out = append(out, ev)
		}
	}
	return out
}

// x86 page-fault error-code bits, as printed in segfault lines.
const (
	errProt  = 0x1  // 0: page not present; 1: protection violation
	errWrite = 0x2  // 0: read; 1: write
	errUser  = 0x4  // 0: kernel mode; 1: user mode
	errRsvd  = 0x8  // reserved bit set in a page-table entry
	errInstr = 0x10 // instruction fetch
)

// DecodeSegfaultError translates the x86 page-fault error code from a
// segfault line into what the process was doing, e.g. error 4 = user-mode
// read of an unmapped address (the classic NULL dereference), error 6 =
// user-mode write, error 14/15 = jump to a bad address.
func DecodeSegfaultError(code int) string {
	var action string
	switch {
	case code&errInstr != 0:
		action = "instruction fetch from"
	case code&errWrite != 0:
		action = "write to"
	default:
		action = "read from"
	}
	var target string
	if code&errProt != 0 {
		target = "a mapped but protected address (permission violation, e.g. writing a read-only page)"
	} else {
		target = "an unmapped address (NULL/dangling pointer territory)"
	}
	mode := "kernel-mode"
	if code&errUser != 0 {
		mode = "user-mode"
	}
	s := fmt.Sprintf("%s %s %s", mode, action, target)
	if code&errRsvd != 0 {
		s += "; reserved page-table bit set (possible memory corruption)"
	}
	return s
}
