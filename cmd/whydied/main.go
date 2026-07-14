// Command whydied explains why a process died: it decodes exit codes and
// signals, hunts the kernel log for OOM-kill and crash records, and reads
// cgroup memory counters, then renders one evidence-backed verdict.
package main

import (
	"os"

	"github.com/JaydenCJ/whydied/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
