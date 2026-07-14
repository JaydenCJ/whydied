// Explain commands: `whydied code <n>` and `whydied signal <name|n>` —
// the pure knowledge-base lookups, no OS access.
package cli

import (
	"flag"
	"fmt"
	"io"
	"strconv"

	"github.com/JaydenCJ/whydied/internal/exitcode"
	"github.com/JaydenCJ/whydied/internal/signals"
)

// runCode explains one exit code.
func runCode(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("code", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "machine-readable output")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	if len(pos) != 1 {
		return usageErr(stderr, "usage: whydied code <exit-code>")
	}
	n, err := strconv.Atoi(pos[0])
	if err != nil {
		return usageErr(stderr, "not an exit code: %q", pos[0])
	}
	exp, err := exitcode.Explain(n)
	if err != nil {
		return usageErr(stderr, "%v", err)
	}
	if *jsonOut {
		if err := writeJSON(stdout, "exit_code", exp); err != nil {
			return runtimeErr(stderr, "%v", err)
		}
		return ExitOK
	}
	renderExitCode(exp, stdout)
	return ExitOK
}

func renderExitCode(exp exitcode.Explanation, w io.Writer) {
	name := ""
	if exp.Name != "" {
		name = " (" + exp.Name + ")"
	}
	fmt.Fprintf(w, "exit code %d%s: %s\n", exp.Code, name, exp.Summary)
	fmt.Fprintf(w, "class: %s\n", exp.Class)
	if len(exp.Detail) > 0 {
		fmt.Fprintf(w, "\nwhat it usually means:\n")
		for _, d := range exp.Detail {
			fmt.Fprintf(w, "  - %s\n", d)
		}
	}
	if exp.Signal != nil {
		fmt.Fprintf(w, "\nthe signal behind it:\n")
		renderSignal(*exp.Signal, w, "  ")
		fmt.Fprintf(w, "\nto move from \"usually\" to evidence: rerun it as `whydied run -- <cmd>`, or post-mortem with `whydied pid <pid> --kmsg <kernel log>`\n")
	}
}

// runSignal explains one signal.
func runSignal(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("signal", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "machine-readable output")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	if len(pos) != 1 {
		return usageErr(stderr, "usage: whydied signal <name|number>")
	}
	sig, err := signals.Parse(pos[0])
	if err != nil {
		return usageErr(stderr, "%v", err)
	}
	if *jsonOut {
		if err := writeJSON(stdout, "signal", sig); err != nil {
			return runtimeErr(stderr, "%v", err)
		}
		return ExitOK
	}
	renderSignal(sig, stdout, "")
	fmt.Fprintf(stdout, "shell reports a death by this signal as exit code %d (128+%d)\n", 128+sig.Number, sig.Number)
	return ExitOK
}

func renderSignal(sig signals.Info, w io.Writer, indent string) {
	label := fmt.Sprintf("%s (signal %d)", sig.Name, sig.Number)
	if sig.Name == fmt.Sprintf("signal %d", sig.Number) {
		label = sig.Name // glibc-reserved 32/33 have no conventional name
	}
	fmt.Fprintf(w, "%s%s: %s\n", indent, label, sig.Description)
	fmt.Fprintf(w, "%sdefault action: %s", indent, sig.Default)
	if !sig.Catchable {
		fmt.Fprintf(w, " — cannot be caught, blocked, or ignored")
	}
	fmt.Fprintln(w)
	if len(sig.Causes) > 0 {
		fmt.Fprintf(w, "%stypical causes:\n", indent)
		for _, c := range sig.Causes {
			fmt.Fprintf(w, "%s  - %s\n", indent, c)
		}
	}
}
