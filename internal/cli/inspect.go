// Post-mortem commands: `whydied pid` diagnoses one PID against the
// kernel log and cgroup counters; `whydied scan` lists every recorded
// death. Both read the log from --kmsg (file or "-") or, by default,
// from /dev/kmsg on the live host.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/JaydenCJ/whydied/internal/cgroup"
	"github.com/JaydenCJ/whydied/internal/kmsg"
	"github.com/JaydenCJ/whydied/internal/verdict"
)

// loadEvents reads kernel-log events from the --kmsg source: a file path,
// "-" for stdin, or (when empty) the live /dev/kmsg buffer.
func loadEvents(kmsgPath string, stdin io.Reader) ([]kmsg.Event, error) {
	switch kmsgPath {
	case "-":
		return kmsg.Parse(stdin)
	case "":
		return readDevKmsg()
	default:
		f, err := os.Open(kmsgPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return kmsg.Parse(f)
	}
}

// readDevKmsg drains the kernel ring buffer via /dev/kmsg. The device
// never returns EOF, so it must be opened non-blocking and read until
// EAGAIN; each read(2) yields exactly one record.
func readDevKmsg() ([]kmsg.Event, error) {
	fd, err := syscall.Open("/dev/kmsg", syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/kmsg: %w (try sudo, `dmesg | whydied scan --kmsg -`, or --kmsg <file>)", err)
	}
	defer syscall.Close(fd)
	var events []kmsg.Event
	buf := make([]byte, 8192)
	for {
		n, err := syscall.Read(fd, buf)
		if err != nil {
			if err == syscall.EAGAIN {
				return events, nil // buffer drained
			}
			if err == syscall.EPIPE {
				continue // record overwritten under us; skip forward
			}
			return events, fmt.Errorf("read /dev/kmsg: %w", err)
		}
		if n == 0 {
			return events, nil
		}
		if ev, ok := kmsg.ParseLine(strings.TrimRight(string(buf[:n]), "\n")); ok {
			events = append(events, ev)
		}
	}
}

// runPID post-mortems one PID.
func runPID(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pid", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "machine-readable output")
	kmsgPath := fs.String("kmsg", "", "kernel log file (\"-\" = stdin; default /dev/kmsg)")
	cgroupDir := fs.String("cgroup", "", "cgroup directory to read memory evidence from")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	if len(pos) != 1 {
		return usageErr(stderr, "usage: whydied pid <pid> [--kmsg file] [--cgroup dir]")
	}
	pid, err := strconv.Atoi(pos[0])
	if err != nil || pid <= 0 {
		return usageErr(stderr, "not a pid: %q", pos[0])
	}

	events, err := loadEvents(*kmsgPath, os.Stdin)
	if err != nil {
		return runtimeErr(stderr, "%v", err)
	}
	in := verdict.Input{PID: pid, Events: events, KmsgSearched: true}
	if *cgroupDir != "" {
		snap, err := cgroup.Read(*cgroupDir)
		if err != nil {
			return runtimeErr(stderr, "%v", err)
		}
		in.Cgroup = &snap
	}
	v := verdict.Diagnose(in)
	if *jsonOut {
		if err := writeJSON(stdout, "verdict", v); err != nil {
			return runtimeErr(stderr, "%v", err)
		}
		return ExitOK
	}
	verdict.Render(v, stdout)
	return ExitOK
}

// runScan lists every death event in the kernel log.
func runScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "machine-readable output")
	kmsgPath := fs.String("kmsg", "", "kernel log file (\"-\" = stdin; default /dev/kmsg)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	if len(pos) != 0 {
		return usageErr(stderr, "usage: whydied scan [--kmsg file]")
	}
	events, err := loadEvents(*kmsgPath, os.Stdin)
	if err != nil {
		return runtimeErr(stderr, "%v", err)
	}
	if *jsonOut {
		if err := writeJSON(stdout, "events", events); err != nil {
			return runtimeErr(stderr, "%v", err)
		}
		return ExitOK
	}
	deaths := 0
	for _, ev := range events {
		fmt.Fprintln(stdout, scanLine(ev))
		if ev.Kind == kmsg.KindOOMKill || ev.Kind == kmsg.KindSegfault || ev.Kind == kmsg.KindTrap {
			deaths++
		}
	}
	fmt.Fprintf(stdout, "whydied scan: %d %s, %d process %s\n",
		len(events), plural(len(events), "event"), deaths, plural(deaths, "death"))
	return ExitOK
}

// plural appends "s" to noun unless n is exactly 1.
func plural(n int, noun string) string {
	if n == 1 {
		return noun
	}
	return noun + "s"
}

// scanLine renders one event as a compact, grep-friendly line.
func scanLine(ev kmsg.Event) string {
	var b strings.Builder
	if ev.Timestamp != "" {
		fmt.Fprintf(&b, "[%s] ", ev.Timestamp)
	}
	fmt.Fprintf(&b, "%-11s", ev.Kind)
	if ev.PID != 0 {
		fmt.Fprintf(&b, " pid=%d", ev.PID)
	}
	if ev.Comm != "" {
		fmt.Fprintf(&b, " comm=%s", ev.Comm)
	}
	switch ev.Kind {
	case kmsg.KindOOMKill:
		if ev.AnonRSSKB > 0 {
			fmt.Fprintf(&b, " anon-rss=%s", cgroup.FormatBytes(ev.AnonRSSKB*1024))
		}
		if ev.CgroupConstrained {
			fmt.Fprintf(&b, " constraint=cgroup-limit")
		} else {
			fmt.Fprintf(&b, " constraint=host-oom")
		}
	case kmsg.KindOOMSummary:
		if ev.OOMMemcg != "" {
			fmt.Fprintf(&b, " oom_memcg=%s", ev.OOMMemcg)
		}
	case kmsg.KindSegfault:
		fmt.Fprintf(&b, " addr=%s err=%d", ev.Addr, ev.ErrCode)
		if ev.Object != "" {
			fmt.Fprintf(&b, " in=%s", ev.Object)
		}
	case kmsg.KindTrap:
		fmt.Fprintf(&b, " trap=%q", ev.TrapName)
	}
	return b.String()
}
