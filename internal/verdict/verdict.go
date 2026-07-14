// Package verdict combines every piece of available evidence — how the
// process ended (wait status or exit code), kernel-log events, and cgroup
// memory counters — into a single ranked diagnosis with an explicit
// confidence level and the evidence lines that back it. The engine is a
// pure function over its Input, so every rule is unit-testable.
package verdict

import (
	"fmt"
	"io"
	"strings"

	"github.com/JaydenCJ/whydied/internal/cgroup"
	"github.com/JaydenCJ/whydied/internal/exitcode"
	"github.com/JaydenCJ/whydied/internal/kmsg"
	"github.com/JaydenCJ/whydied/internal/signals"
	"github.com/JaydenCJ/whydied/internal/waitinfo"
)

// Confidence grades how strongly the evidence supports the verdict.
type Confidence string

const (
	// Confirmed: direct kernel or cgroup evidence names this death.
	Confirmed Confidence = "confirmed"
	// Likely: the death signature plus circumstantial evidence point one
	// way, but no kernel record ties it to this process.
	Likely Confidence = "likely"
	// Possible: consistent hypotheses remain; more evidence needed.
	Possible Confidence = "possible"
	// Info: nothing died abnormally, or the code speaks for itself.
	Info Confidence = "info"
)

// Cause identifiers, stable for JSON consumers.
const (
	CauseOOMCgroup      = "oom-kill-cgroup"
	CauseOOMGlobal      = "oom-kill-global"
	CauseSegfault       = "segfault"
	CauseTrap           = "fatal-trap"
	CauseSignal         = "fatal-signal"
	CauseSignalInferred = "fatal-signal-inferred"
	CauseExitCode       = "exit-code"
	CauseCleanExit      = "clean-exit"
	CauseUnknown        = "unknown"
)

// Evidence is one sourced fact supporting the verdict.
type Evidence struct {
	Source string `json:"source"` // "kernel log", "cgroup", "wait status", "exit code", "rusage"
	Detail string `json:"detail"`
}

// Verdict is the diagnosis: one headline, one cause, one confidence, and
// the receipts.
type Verdict struct {
	Cause      string     `json:"cause"`
	Confidence Confidence `json:"confidence"`
	Headline   string     `json:"headline"`
	PID        int        `json:"pid,omitempty"`
	Comm       string     `json:"comm,omitempty"`
	Evidence   []Evidence `json:"evidence"`
	Advice     []string   `json:"advice"`
}

// Input carries everything the caller managed to collect. All fields are
// optional; the engine uses what it gets.
type Input struct {
	Death *waitinfo.Death // how the process ended, if observed
	PID   int             // subject PID, if known
	Comm  string          // subject command name, if known
	// Events are parsed kernel-log records (already filtered or not —
	// the engine matches on PID itself).
	Events []kmsg.Event
	// KmsgSearched tells the engine whether a kernel log was actually
	// available: "no OOM record" only means something if we looked.
	KmsgSearched bool
	// Cgroup is a snapshot of the subject's cgroup; CgroupBefore, when
	// present, enables delta analysis around a supervised run.
	Cgroup       *cgroup.Snapshot
	CgroupBefore *cgroup.Snapshot
	// MaxRSSKiB is the peak resident set from rusage, if supervised.
	MaxRSSKiB int64
}

// Diagnose weighs the evidence and returns the strongest supported
// verdict. Rules are ordered hard-evidence-first: a kernel OOM record
// beats any amount of exit-code folklore.
func Diagnose(in Input) Verdict {
	events := in.Events
	if in.PID != 0 {
		events = kmsg.ForPID(in.Events, in.PID)
	}

	if v, ok := diagnoseOOM(in, events); ok {
		return v
	}
	if v, ok := diagnoseFault(in, events); ok {
		return v
	}
	if v, ok := diagnoseCgroupDelta(in); ok {
		return v
	}
	if in.Death != nil {
		return diagnoseFromDeath(in)
	}
	return unknownVerdict(in)
}

// diagnoseOOM looks for a kernel OOM-kill record for the subject.
func diagnoseOOM(in Input, events []kmsg.Event) (Verdict, bool) {
	var kill *kmsg.Event
	var summary *kmsg.Event
	for i := range events {
		switch events[i].Kind {
		case kmsg.KindOOMKill:
			if kill == nil {
				kill = &events[i]
			}
		case kmsg.KindOOMSummary:
			if summary == nil {
				summary = &events[i]
			}
		}
	}
	if kill == nil && summary == nil {
		return Verdict{}, false
	}

	v := Verdict{Confidence: Confirmed, PID: in.PID, Comm: in.Comm}
	cgroupConstrained := (kill != nil && kill.CgroupConstrained) || (summary != nil && summary.CgroupConstrained)
	if v.Comm == "" {
		if kill != nil {
			v.Comm = kill.Comm
		} else {
			v.Comm = summary.Comm
		}
	}
	if v.PID == 0 {
		if kill != nil {
			v.PID = kill.PID
		} else {
			v.PID = summary.PID
		}
	}

	if cgroupConstrained {
		v.Cause = CauseOOMCgroup
		v.Headline = fmt.Sprintf("%s was killed by the kernel OOM killer: its cgroup hit the memory limit", subject(v.Comm, v.PID))
	} else {
		v.Cause = CauseOOMGlobal
		v.Headline = fmt.Sprintf("%s was killed by the kernel OOM killer: the host ran out of memory", subject(v.Comm, v.PID))
	}

	if kill != nil {
		v.Evidence = append(v.Evidence, Evidence{"kernel log", quoteEvent(*kill)})
		if kill.AnonRSSKB > 0 {
			v.Evidence = append(v.Evidence, Evidence{"kernel log",
				fmt.Sprintf("at kill time the process held anon-rss %s, total-vm %s",
					cgroup.FormatBytes(kill.AnonRSSKB*1024), cgroup.FormatBytes(kill.TotalVMKB*1024))})
		}
		if kill.OOMScoreAdj != nil && *kill.OOMScoreAdj != 0 {
			v.Evidence = append(v.Evidence, Evidence{"kernel log",
				fmt.Sprintf("oom_score_adj was %d — victim selection was biased", *kill.OOMScoreAdj)})
		}
	}
	if summary != nil {
		if summary.OOMMemcg != "" {
			v.Evidence = append(v.Evidence, Evidence{"kernel log",
				fmt.Sprintf("the cgroup that hit its limit: %s (constraint %s)", summary.OOMMemcg, summary.Constraint)})
		} else {
			v.Evidence = append(v.Evidence, Evidence{"kernel log", quoteEvent(*summary)})
		}
	}
	appendCgroupEvidence(&v, in)

	if cgroupConstrained {
		v.Advice = []string{
			"raise the cgroup limit (cgroup v2 memory.max; Kubernetes resources.limits.memory; docker --memory) or shrink the workload",
			"compare memory.peak against memory.max over time — a slow climb to the limit means a leak, an instant hit means undersizing",
			"in Kubernetes this surfaces as OOMKilled / exit code 137 in `kubectl describe pod`",
		}
	} else {
		v.Advice = []string{
			"the whole host was out of memory: audit what else runs there, add RAM or swap, or set per-service limits so the right thing dies",
			"the kernel picks the victim by oom_score; protect critical services with OOMScoreAdjust (systemd) or oom_score_adj",
		}
	}
	return v, true
}

// diagnoseFault handles segfault and trap records.
func diagnoseFault(in Input, events []kmsg.Event) (Verdict, bool) {
	for _, ev := range events {
		switch ev.Kind {
		case kmsg.KindSegfault:
			v := Verdict{
				Cause:      CauseSegfault,
				Confidence: Confirmed,
				PID:        ev.PID,
				Comm:       ev.Comm,
				Headline:   fmt.Sprintf("%s crashed with a segmentation fault (SIGSEGV)", subject(ev.Comm, ev.PID)),
			}
			v.Evidence = append(v.Evidence, Evidence{"kernel log", quoteEvent(ev)})
			v.Evidence = append(v.Evidence, Evidence{"kernel log",
				fmt.Sprintf("fault decode: %s (address 0x%s)", kmsg.DecodeSegfaultError(ev.ErrCode), strings.TrimPrefix(ev.Addr, "0x"))})
			if ev.Object != "" {
				v.Evidence = append(v.Evidence, Evidence{"kernel log",
					fmt.Sprintf("faulting instruction was inside %s", ev.Object)})
			}
			v.Advice = []string{
				"this is a bug in the program (or a library it loads), not the environment — get a core dump or run under a debugger",
				"enable cores: `ulimit -c unlimited` (or coredumpctl on systemd hosts), reproduce, then inspect with gdb/dlv",
				"if the address is 0 or near-0, suspect a NULL pointer; a huge address suggests corruption or a bad index",
			}
			return v, true
		case kmsg.KindTrap:
			name := ev.TrapName
			sig := trapSignal(name)
			v := Verdict{
				Cause:      CauseTrap,
				Confidence: Confirmed,
				PID:        ev.PID,
				Comm:       ev.Comm,
				Headline:   fmt.Sprintf("%s died on a CPU fault: %s (%s)", subject(ev.Comm, ev.PID), name, sig),
			}
			v.Evidence = append(v.Evidence, Evidence{"kernel log", quoteEvent(ev)})
			if ev.Object != "" {
				v.Evidence = append(v.Evidence, Evidence{"kernel log",
					fmt.Sprintf("faulting instruction was inside %s", ev.Object)})
			}
			v.Advice = adviceForTrap(name)
			return v, true
		}
	}
	return Verdict{}, false
}

// trapSignal maps a kernel trap name to the signal the process received.
func trapSignal(name string) string {
	switch {
	case strings.Contains(name, "divide"):
		return "SIGFPE"
	case strings.Contains(name, "invalid opcode"):
		return "SIGILL"
	case strings.Contains(name, "general protection"):
		return "SIGSEGV"
	default:
		return "fatal signal"
	}
}

func adviceForTrap(name string) []string {
	switch {
	case strings.Contains(name, "divide"):
		return []string{
			"an integer division by zero (or INT_MIN / -1) executed — find the division with a debugger or the ip: offset",
		}
	case strings.Contains(name, "invalid opcode"):
		return []string{
			"the CPU refused an instruction: a binary built for newer hardware (AVX-512 etc.), corrupted code, or a jump into data",
			"check `lscpu` flags against the build target; try a generic build of the same program",
		}
	default:
		return []string{
			"a general protection fault is memory corruption territory — same playbook as a segfault: core dump plus debugger",
		}
	}
}

// diagnoseCgroupDelta fires when a supervised run saw the cgroup's
// oom_kill counter move even though no kernel log was readable.
func diagnoseCgroupDelta(in Input) (Verdict, bool) {
	if in.Cgroup == nil || in.CgroupBefore == nil {
		return Verdict{}, false
	}
	if in.Cgroup.OOMKills < 0 || in.CgroupBefore.OOMKills < 0 || in.Cgroup.OOMKills <= in.CgroupBefore.OOMKills {
		return Verdict{}, false
	}
	v := Verdict{
		Cause:      CauseOOMCgroup,
		Confidence: Confirmed,
		PID:        in.PID,
		Comm:       in.Comm,
		Headline:   fmt.Sprintf("%s was OOM-killed inside its cgroup (kill counter advanced during the run)", subject(in.Comm, in.PID)),
	}
	v.Evidence = append(v.Evidence, Evidence{"cgroup",
		fmt.Sprintf("memory.events oom_kill went %d -> %d during the run (%s)",
			in.CgroupBefore.OOMKills, in.Cgroup.OOMKills, in.Cgroup.Path)})
	appendCgroupEvidence(&v, in)
	appendDeathEvidence(&v, in)
	v.Advice = []string{
		"raise the cgroup limit (memory.max / resources.limits.memory / docker --memory) or reduce the workload's footprint",
		"pass --kmsg to attach the kernel's own kill record with per-process memory accounting",
	}
	return v, true
}

// diagnoseFromDeath handles the no-kernel-evidence tiers: signal deaths
// and plain exit codes.
func diagnoseFromDeath(in Input) Verdict {
	d := *in.Death
	switch {
	case d.Signaled && !d.Inferred:
		return diagnoseSignal(in, d, false)
	case d.Signaled && d.Inferred:
		return diagnoseSignal(in, d, true)
	case d.Exited && d.ExitCode == 0:
		v := Verdict{
			Cause:      CauseCleanExit,
			Confidence: Info,
			PID:        in.PID,
			Comm:       in.Comm,
			Headline:   fmt.Sprintf("%s exited cleanly (code 0) — nothing to explain", subject(in.Comm, in.PID)),
		}
		appendDeathEvidence(&v, in)
		return v
	default:
		exp, err := exitcode.Explain(d.ExitCode)
		v := Verdict{
			Cause:      CauseExitCode,
			Confidence: Info,
			PID:        in.PID,
			Comm:       in.Comm,
		}
		if err != nil {
			v.Cause = CauseUnknown
			v.Headline = err.Error()
			return v
		}
		v.Headline = fmt.Sprintf("%s exited with code %d: %s", subject(in.Comm, in.PID), d.ExitCode, exp.Summary)
		appendDeathEvidence(&v, in)
		v.Advice = append(v.Advice, exp.Detail...)
		return v
	}
}

// diagnoseSignal builds the verdict for a signal death without kernel-log
// confirmation, grading confidence by what circumstantial evidence shows.
func diagnoseSignal(in Input, d waitinfo.Death, inferred bool) Verdict {
	sig, ok := signals.ByNumber(d.Signal)
	if !ok {
		return unknownVerdict(in)
	}
	cause := CauseSignal
	if inferred {
		cause = CauseSignalInferred
	}
	v := Verdict{
		Cause:      cause,
		Confidence: Likely,
		PID:        in.PID,
		Comm:       in.Comm,
	}
	appendDeathEvidence(&v, in)
	if inferred {
		v.Evidence = append(v.Evidence, Evidence{"exit code",
			fmt.Sprintf("inferred from the 128+N convention (%d = 128+%d); the program could also have called exit(%d) itself", d.ExitCode, sig.Number, d.ExitCode)})
	}

	if sig.Number == 9 { // SIGKILL: the OOM-or-operator fork
		nearLimit := in.Cgroup != nil && in.Cgroup.NearLimit()
		switch {
		case nearLimit:
			v.Cause = CauseOOMCgroup
			v.Headline = fmt.Sprintf("%s was killed by SIGKILL, most likely the OOM killer: its cgroup was running at the memory limit", subject(in.Comm, in.PID))
			appendCgroupEvidence(&v, in)
			v.Advice = append(v.Advice,
				"confirm with the kernel log: `sudo dmesg | whydied scan --kmsg -` (or journalctl -k), or rerun under `whydied run`",
				"raise the cgroup limit or shrink the workload; the peak/limit ratio above says how much headroom was left")
		case in.KmsgSearched:
			v.Confidence = Likely
			v.Headline = fmt.Sprintf("%s was killed by SIGKILL from outside the kernel (no OOM record in the searched kernel log)", subject(in.Comm, in.PID))
			v.Evidence = append(v.Evidence, Evidence{"kernel log", "searched: no OOM-kill or fault record mentions this process"})
			v.Advice = append(v.Advice,
				"look for an explicit `kill -9`: an operator, a supervisor timeout (systemd TimeoutStopSec, Docker stop grace period), or a batch scheduler",
				"note the searched log covers the current boot / provided capture only — an older record may have rotated away")
		default:
			v.Confidence = Possible
			v.Headline = fmt.Sprintf("%s was killed by SIGKILL — the OOM killer and an external kill are both open (no kernel log was available)", subject(in.Comm, in.PID))
			v.Advice = append(v.Advice,
				"get the kernel's word: `sudo dmesg | whydied scan --kmsg -`, or pass --kmsg <file> with a saved capture",
				"if this ran in Kubernetes/Docker, check `kubectl describe pod` for OOMKilled or `docker inspect` .State.OOMKilled")
		}
		if in.MaxRSSKiB > 0 {
			v.Evidence = append(v.Evidence, Evidence{"rusage",
				fmt.Sprintf("peak resident set during the run: %s", cgroup.FormatBytes(in.MaxRSSKiB*1024))})
		}
		return v
	}

	verb := "was killed by"
	if sig.KernelSent {
		verb = "died of"
	}
	v.Headline = fmt.Sprintf("%s %s %s: %s", subject(in.Comm, in.PID), verb, sig.Name, sig.Description)
	if d.CoreDumped {
		v.Evidence = append(v.Evidence, Evidence{"wait status", "the kernel wrote a core dump — inspect it with gdb or coredumpctl"})
	}
	v.Advice = append(v.Advice, sig.Causes...)
	if !sig.Fatal() {
		v.Confidence = Info
	}
	return v
}

func unknownVerdict(in Input) Verdict {
	v := Verdict{
		Cause:      CauseUnknown,
		Confidence: Possible,
		PID:        in.PID,
		Comm:       in.Comm,
		Headline:   fmt.Sprintf("no death record found for %s in the evidence provided", subject(in.Comm, in.PID)),
	}
	if in.KmsgSearched {
		v.Evidence = append(v.Evidence, Evidence{"kernel log", "searched: no OOM-kill, segfault, or trap record mentions this process"})
	}
	v.Advice = []string{
		"the kernel only logs deaths it caused (OOM kills, faults); a clean exit or an external signal leaves no kernel record",
		"widen the search: `whydied scan --kmsg <file>` lists every death in a capture; check the supervisor's logs (systemd, containerd, k8s events) for the rest",
	}
	return v
}

// appendCgroupEvidence adds limit/peak context from the cgroup snapshot.
func appendCgroupEvidence(v *Verdict, in Input) {
	s := in.Cgroup
	if s == nil {
		return
	}
	if s.MaxBytes != cgroup.Unknown {
		line := fmt.Sprintf("cgroup (v%d) memory limit: %s", s.Version, cgroup.FormatBytes(s.MaxBytes))
		if s.PeakBytes >= 0 {
			line += fmt.Sprintf(", observed peak: %s", cgroup.FormatBytes(s.PeakBytes))
		}
		v.Evidence = append(v.Evidence, Evidence{"cgroup", line})
	}
	if s.OOMKills > 0 && in.CgroupBefore == nil {
		v.Evidence = append(v.Evidence, Evidence{"cgroup",
			fmt.Sprintf("lifetime oom_kill counter in %s: %d", s.Path, s.OOMKills)})
	}
}

// appendDeathEvidence records how the process ended, when observed.
func appendDeathEvidence(v *Verdict, in Input) {
	if in.Death == nil {
		return
	}
	source := "wait status"
	if in.Death.Inferred {
		source = "exit code"
	}
	v.Evidence = append(v.Evidence, Evidence{source, in.Death.Describe()})
}

// subject renders "comm (pid N)" from whatever identity is known.
func subject(comm string, pid int) string {
	switch {
	case comm != "" && pid != 0:
		return fmt.Sprintf("%s (pid %d)", comm, pid)
	case comm != "":
		return comm
	case pid != 0:
		return fmt.Sprintf("pid %d", pid)
	default:
		return "the process"
	}
}

func quoteEvent(ev kmsg.Event) string {
	if ev.Timestamp != "" {
		return fmt.Sprintf("[%s] %s", ev.Timestamp, ev.Message)
	}
	return ev.Message
}

// Render writes the verdict as the human-readable report the CLI prints.
func Render(v Verdict, w io.Writer) {
	fmt.Fprintf(w, "verdict: %s\n", v.Headline)
	fmt.Fprintf(w, "cause: %s   confidence: %s\n", v.Cause, v.Confidence)
	if len(v.Evidence) > 0 {
		fmt.Fprintf(w, "\nevidence:\n")
		for _, e := range v.Evidence {
			fmt.Fprintf(w, "  [%s] %s\n", e.Source, e.Detail)
		}
	}
	if len(v.Advice) > 0 {
		fmt.Fprintf(w, "\nadvice:\n")
		for _, a := range v.Advice {
			fmt.Fprintf(w, "  - %s\n", a)
		}
	}
}
