// The `run` command: supervise a child command and diagnose its death on
// the spot. whydied stays out of the data path — the child inherits
// stdio, the diagnosis goes to stderr, and the child's shell code is
// passed through — so `whydied run -- cmd` can wrap anything in a
// pipeline or a container ENTRYPOINT without changing behavior.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/JaydenCJ/whydied/internal/cgroup"
	"github.com/JaydenCJ/whydied/internal/verdict"
	"github.com/JaydenCJ/whydied/internal/waitinfo"
)

// runRun supervises a command. Exit code: the child's shell code
// (128+signal for signal deaths), or 127/126 shell-style when the child
// cannot be started at all.
func runRun(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "machine-readable diagnosis on stderr")
	kmsgPath := fs.String("kmsg", "", "kernel log file to search after an abnormal death (\"-\" = stdin; default /dev/kmsg)")
	cgroupDir := fs.String("cgroup", "", "cgroup directory to watch (default: whydied's own cgroup)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return usageErr(stderr, "usage: whydied run [flags] -- <command> [args...]")
	}

	// Snapshot the cgroup before the child runs so the oom_kill counter
	// delta is attributable to this run.
	dir := *cgroupDir
	if dir == "" {
		dir, _ = cgroup.SelfDir() // best effort; empty on failure
	}
	var before *cgroup.Snapshot
	if dir != "" {
		if snap, err := cgroup.Read(dir); err == nil {
			before = &snap
		}
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return startFailure(err, argv[0], stderr)
	}
	waitErr := cmd.Wait()

	death := deathOf(cmd.ProcessState, waitErr)
	if death.Exited && death.ExitCode == 0 && !death.Signaled {
		return 0 // transparent success: no report, no noise
	}

	in := verdict.Input{
		Death:        &death,
		PID:          cmd.ProcessState.Pid(),
		Comm:         filepath.Base(argv[0]),
		CgroupBefore: before,
	}
	if before != nil {
		if snap, err := cgroup.Read(dir); err == nil {
			in.Cgroup = &snap
		}
	}
	if events, err := loadEvents(*kmsgPath, os.Stdin); err == nil {
		in.Events = events
		in.KmsgSearched = true
	}
	if ru, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok && ru != nil {
		in.MaxRSSKiB = int64(ru.Maxrss)
	}

	v := verdict.Diagnose(in)
	if *jsonOut {
		if err := writeJSON(stderr, "verdict", v); err != nil {
			fmt.Fprintf(stderr, "whydied: %v\n", err)
		}
	} else {
		fmt.Fprintf(stderr, "\n--- whydied ---\n")
		verdict.Render(v, stderr)
	}
	return death.ShellCode()
}

// deathOf decodes how the child ended from its ProcessState, falling back
// to the plain exit code if the platform wait status is unavailable.
func deathOf(ps *os.ProcessState, waitErr error) waitinfo.Death {
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok {
		switch {
		case ws.Exited():
			return waitinfo.Death{Exited: true, ExitCode: ws.ExitStatus()}
		case ws.Signaled():
			return waitinfo.Death{
				Signaled:   true,
				Signal:     int(ws.Signal()),
				CoreDumped: ws.CoreDump(),
			}
		}
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return waitinfo.FromExitCode(exitErr.ExitCode())
	}
	return waitinfo.Death{Exited: true, ExitCode: ps.ExitCode()}
}

// startFailure maps "could not even start" errors onto the shell
// conventions whydied itself documents: 127 not found, 126 not
// executable.
func startFailure(err error, name string, stderr io.Writer) int {
	fmt.Fprintf(stderr, "whydied: cannot start %s: %v\n", name, err)
	switch {
	case errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist):
		fmt.Fprintf(stderr, "whydied: exiting 127 (command not found) — see `whydied code 127`\n")
		return 127
	case errors.Is(err, fs.ErrPermission):
		fmt.Fprintf(stderr, "whydied: exiting 126 (found but not executable) — see `whydied code 126`\n")
		return 126
	default:
		return ExitRuntime
	}
}
