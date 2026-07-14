// Package cli implements the whydied command-line interface. Run takes
// argv and two writers and returns an exit code, so the whole surface is
// testable in-process without building a binary.
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strconv"

	"github.com/JaydenCJ/whydied/internal/version"
)

// Exit codes for whydied itself. `run` is the exception: it passes the
// child's shell code through so pipelines behave as if unwrapped.
const (
	ExitOK      = 0
	ExitUsage   = 2
	ExitRuntime = 3
)

// Run dispatches argv and returns the process exit code. A bare number as
// the first argument is a shortcut for `code` — `whydied 137` just works.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stdout)
		return ExitOK
	}
	if _, err := strconv.Atoi(args[0]); err == nil {
		return runCode(args, stdout, stderr)
	}
	switch args[0] {
	case "code":
		return runCode(args[1:], stdout, stderr)
	case "signal":
		return runSignal(args[1:], stdout, stderr)
	case "run":
		return runRun(args[1:], stdout, stderr)
	case "pid":
		return runPID(args[1:], stdout, stderr)
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "whydied %s\n", version.Version)
		return ExitOK
	case "help", "--help", "-h":
		usage(stdout)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "whydied: unknown command %q\n\n", args[0])
		usage(stderr)
		return ExitUsage
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `whydied — explain why a process died, with kernel-log evidence.

Usage:
  whydied <command> [flags] [args]
  whydied <exit-code>              shortcut for "whydied code <exit-code>"

Commands:
  code <n>            explain an exit code (0-255): conventions, 128+N signals
  signal <name|n>     explain a signal: default action, core dumps, typical causes
  run -- <cmd> …      supervise a command and diagnose its death on the spot
  pid <pid>           post-mortem a PID against the kernel log and cgroup counters
  scan                list every process death recorded in the kernel log
  version             print the whydied version

Common flags:
  --json              machine-readable output (schema_version 1)
  --kmsg <file>       read the kernel log from a file ("-" = stdin) instead of /dev/kmsg
  --cgroup <dir>      read memory evidence from this cgroup directory

Exit codes: 0 ok, 2 usage error, 3 runtime error.
"run" instead passes the child's status through (128+signal for signal deaths).
`)
}

// envelope is the stable JSON wrapper for --json output.
type envelope struct {
	Tool          string `json:"tool"`
	SchemaVersion int    `json:"schema_version"`
	Version       string `json:"version"`
	Kind          string `json:"kind"`
	Data          any    `json:"data"`
}

// writeJSON emits the envelope; kind names the payload ("verdict",
// "exit_code", "signal", "events").
func writeJSON(w io.Writer, kind string, data any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope{
		Tool:          "whydied",
		SchemaVersion: 1,
		Version:       version.Version,
		Kind:          kind,
		Data:          data,
	})
}

// parseInterspersed parses fs while allowing flags to follow positional
// arguments (`whydied pid 1337 --kmsg log` and `whydied pid --kmsg log
// 1337` both work). Go's flag package stops at the first positional, so
// this re-parses the remainder after collecting each one. Negative
// numbers (`whydied code -1`) are taken as positionals, not flags, so
// they reach the knowledge base's own out-of-range explanation. Not used
// by `run`, where everything after the command belongs to the child.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		for len(args) > 0 && isNegativeNumber(args[0]) {
			pos = append(pos, args[0])
			args = args[1:]
		}
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// isNegativeNumber reports whether arg looks like a negative integer
// ("-1") rather than a flag.
func isNegativeNumber(arg string) bool {
	if len(arg) < 2 || arg[0] != '-' {
		return false
	}
	_, err := strconv.Atoi(arg[1:])
	return err == nil && arg[1] != '+' && arg[1] != '-'
}

// usageErr prints a one-line usage failure and returns ExitUsage.
func usageErr(stderr io.Writer, format string, args ...any) int {
	fmt.Fprintf(stderr, "whydied: "+format+"\n", args...)
	return ExitUsage
}

// runtimeErr prints a runtime failure and returns ExitRuntime.
func runtimeErr(stderr io.Writer, format string, args ...any) int {
	fmt.Fprintf(stderr, "whydied: "+format+"\n", args...)
	return ExitRuntime
}
