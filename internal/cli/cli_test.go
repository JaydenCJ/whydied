// CLI tests: exercise Run in-process, end to end — commands, flags in
// both positions, JSON envelopes, exit-code passthrough for `run`, and
// the documented usage-error contract — without building a binary. The
// only child processes spawned are tiny `sh -c` one-liners that die in
// deterministic ways.
package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureLog = "../../examples/kern.log"

// runCLI invokes Run and captures both streams.
func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// decodeEnvelope asserts the stable JSON wrapper and returns the payload.
func decodeEnvelope(t *testing.T, raw, wantKind string) map[string]any {
	t.Helper()
	var env struct {
		Tool          string         `json:"tool"`
		SchemaVersion int            `json:"schema_version"`
		Kind          string         `json:"kind"`
		Data          map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, raw)
	}
	if env.Tool != "whydied" || env.SchemaVersion != 1 || env.Kind != wantKind {
		t.Fatalf("envelope = %+v", env)
	}
	return env.Data
}

func TestVersionMatchesManifest(t *testing.T) {
	code, out, _ := runCLI(t, "version")
	if code != ExitOK || out != "whydied 0.1.0\n" {
		t.Errorf("version: code=%d out=%q", code, out)
	}
	code, out2, _ := runCLI(t, "--version")
	if code != ExitOK || out2 != out {
		t.Error("--version must match the version subcommand")
	}
}

func TestUsageSurface(t *testing.T) {
	// Bare invocation is help (exit 0); an unknown command is an error
	// (exit 2) with the usage on stderr.
	code, out, _ := runCLI(t)
	if code != ExitOK || !strings.Contains(out, "Usage:") {
		t.Errorf("bare invocation: code=%d", code)
	}
	code, _, errOut := runCLI(t, "frobnicate")
	if code != ExitUsage || !strings.Contains(errOut, "unknown command") {
		t.Errorf("code=%d stderr=%q", code, errOut)
	}
}

func TestBareNumberIsCodeShortcut(t *testing.T) {
	code, out, _ := runCLI(t, "137")
	if code != ExitOK {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(out, "SIGKILL") || !strings.Contains(out, "OOM") {
		t.Errorf("`whydied 137` must reach SIGKILL and the OOM killer:\n%s", out)
	}
}

func TestCodeCommandTextAndJSON(t *testing.T) {
	code, out, _ := runCLI(t, "code", "127")
	if code != ExitOK || !strings.Contains(out, "command not found") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	code, out, _ = runCLI(t, "code", "127", "--json")
	if code != ExitOK {
		t.Fatal("json variant failed")
	}
	data := decodeEnvelope(t, out, "exit_code")
	if data["code"].(float64) != 127 || data["class"] != "exec-failure" {
		t.Errorf("payload = %v", data)
	}
}

func TestCodeCommandRejectsGarbageAndRange(t *testing.T) {
	if code, _, _ := runCLI(t, "code", "banana"); code != ExitUsage {
		t.Error("non-numeric code should exit 2")
	}
	code, _, errOut := runCLI(t, "code", "300")
	if code != ExitUsage || !strings.Contains(errOut, "8 bits") {
		t.Errorf("out-of-range code: code=%d stderr=%q", code, errOut)
	}
	if code, _, _ := runCLI(t, "code"); code != ExitUsage {
		t.Error("missing argument should exit 2")
	}
}

func TestSignalCommandTextAndJSON(t *testing.T) {
	code, byName, _ := runCLI(t, "signal", "segv")
	if code != ExitOK || !strings.Contains(byName, "SIGSEGV (signal 11)") {
		t.Fatalf("code=%d out=%q", code, byName)
	}
	if !strings.Contains(byName, "exit code 139") {
		t.Error("signal explanation should include the 128+N shell code")
	}
	_, byNumber, _ := runCLI(t, "signal", "11")
	if byName != byNumber {
		t.Error("name and number lookups must render identically")
	}
	code, jsonOut, _ := runCLI(t, "signal", "--json", "KILL")
	if code != ExitOK {
		t.Fatal("signal --json failed")
	}
	data := decodeEnvelope(t, jsonOut, "signal")
	if data["number"].(float64) != 9 || data["catchable"] != false {
		t.Errorf("payload = %v", data)
	}
}

func TestScanFixtureCountsAndLines(t *testing.T) {
	code, out, _ := runCLI(t, "scan", "--kmsg", fixtureLog)
	if code != ExitOK {
		t.Fatalf("scan failed: %s", out)
	}
	if !strings.Contains(out, "whydied scan: 9 events, 5 process deaths") {
		t.Errorf("summary line wrong:\n%s", out)
	}
	for _, want := range []string{
		"oom-kill    pid=1337 comm=java",
		"constraint=cgroup-limit",
		"oom-kill    pid=2001 comm=stress",
		"constraint=host-oom",
		"segfault    pid=4242 comm=myapp addr=0 err=4",
		`trap        pid=7707 comm=crasher trap="divide error"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scan output missing %q:\n%s", want, out)
		}
	}
	// --json emits the same nine events in the envelope.
	code, out, _ = runCLI(t, "scan", "--kmsg", fixtureLog, "--json")
	if code != ExitOK {
		t.Fatal("scan --json failed")
	}
	var env struct {
		Kind string           `json:"kind"`
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if env.Kind != "events" || len(env.Data) != 9 {
		t.Errorf("kind=%s events=%d", env.Kind, len(env.Data))
	}
}

func TestScanStdinAndMissingFile(t *testing.T) {
	// --kmsg - reads stdin; feed one line through a pipe.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })
	go func() {
		w.WriteString("[1.000000] Out of memory: Killed process 7 (tiny) total-vm:8kB, anon-rss:4kB, file-rss:0kB, shmem-rss:0kB\n")
		w.Close()
	}()
	code, out, _ := runCLI(t, "scan", "--kmsg", "-")
	if code != ExitOK || !strings.Contains(out, "pid=7 comm=tiny") {
		t.Errorf("code=%d out=%q", code, out)
	}
	// A missing --kmsg file is a runtime error (exit 3), not a panic.
	code, _, errOut := runCLI(t, "scan", "--kmsg", "/nonexistent/kern.log")
	if code != ExitRuntime || errOut == "" {
		t.Errorf("code=%d stderr=%q", code, errOut)
	}
}

func TestPidPostMortemConfirmedOOM(t *testing.T) {
	// Flags after the positional (the natural way to type it).
	code, out, _ := runCLI(t, "pid", "1337", "--kmsg", fixtureLog)
	if code != ExitOK {
		t.Fatalf("pid failed: %s", out)
	}
	for _, want := range []string{
		"verdict: java (pid 1337) was killed by the kernel OOM killer",
		"cause: oom-kill-cgroup   confidence: confirmed",
		"/kubepods.slice/kubepods-burstable.slice/pod7c1a9f2e",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

func TestPidPostMortemSegfault(t *testing.T) {
	code, out, _ := runCLI(t, "pid", "4242", "--kmsg", fixtureLog)
	if code != ExitOK || !strings.Contains(out, "segmentation fault") {
		t.Fatalf("code=%d\n%s", code, out)
	}
	if !strings.Contains(out, "NULL/dangling pointer") {
		t.Error("segfault verdict should decode error 4 at address 0")
	}
}

func TestPidUnknownPidReportsHonestly(t *testing.T) {
	code, out, _ := runCLI(t, "pid", "99999", "--kmsg", fixtureLog)
	if code != ExitOK || !strings.Contains(out, "confidence: possible") {
		t.Fatalf("code=%d\n%s", code, out)
	}
	if !strings.Contains(out, "no death record found") {
		t.Errorf("unknown pid should say so:\n%s", out)
	}
}

func TestPidJSONVerdict(t *testing.T) {
	code, out, _ := runCLI(t, "pid", "--json", "--kmsg", fixtureLog, "1337")
	if code != ExitOK {
		t.Fatal("pid --json failed")
	}
	data := decodeEnvelope(t, out, "verdict")
	if data["cause"] != "oom-kill-cgroup" || data["confidence"] != "confirmed" {
		t.Errorf("payload = %v", data)
	}
}

func TestPidWithCgroupEvidence(t *testing.T) {
	// A fake v2 cgroup directory feeds limit/peak into the verdict.
	dir := t.TempDir()
	files := map[string]string{
		"memory.events":  "low 0\nhigh 0\nmax 9\noom 3\noom_kill 3\n",
		"memory.max":     "536870912\n",
		"memory.peak":    "536870912\n",
		"memory.current": "0\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	code, out, _ := runCLI(t, "pid", "1337", "--kmsg", fixtureLog, "--cgroup", dir)
	if code != ExitOK {
		t.Fatal(out)
	}
	if !strings.Contains(out, "memory limit: 512.0 MiB") {
		t.Errorf("cgroup evidence missing:\n%s", out)
	}
}

func TestPidRejectsBadArguments(t *testing.T) {
	if code, _, _ := runCLI(t, "pid", "zero", "--kmsg", fixtureLog); code != ExitUsage {
		t.Error("non-numeric pid should exit 2")
	}
	if code, _, _ := runCLI(t, "pid", "-5", "--kmsg", fixtureLog); code != ExitUsage {
		t.Error("negative pid should exit 2")
	}
	if code, _, _ := runCLI(t, "pid", "--kmsg", fixtureLog); code != ExitUsage {
		t.Error("missing pid should exit 2")
	}
}

func TestRunPassesThroughCleanExitSilently(t *testing.T) {
	code, out, errOut := runCLI(t, "run", "--", "sh", "-c", "echo payload; exit 0")
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(out, "payload") {
		t.Error("child stdout must pass through")
	}
	if strings.Contains(errOut, "whydied") {
		t.Errorf("clean exits must produce no report:\n%s", errOut)
	}
}

func TestRunDiagnosesNonzeroExitAndPassesCodeThrough(t *testing.T) {
	code, _, errOut := runCLI(t, "run", "--", "sh", "-c", "exit 42")
	if code != 42 {
		t.Fatalf("passthrough code=%d, want 42", code)
	}
	if !strings.Contains(errOut, "exited with code 42") {
		t.Errorf("diagnosis missing:\n%s", errOut)
	}
}

func TestRunObservesRealSignalDeath(t *testing.T) {
	code, _, errOut := runCLI(t, "run", "--", "sh", "-c", "kill -KILL $$")
	if code != 137 {
		t.Fatalf("passthrough code=%d, want 137", code)
	}
	// The wait status makes this a REAL SIGKILL, not an inference.
	if !strings.Contains(errOut, "killed by SIGKILL") {
		t.Errorf("diagnosis:\n%s", errOut)
	}
	if strings.Contains(errOut, "128+N convention") {
		t.Error("a wait-status death must not be labelled as inferred")
	}
	// A SEGV death maps to 139 and is named in the diagnosis.
	code, _, errOut = runCLI(t, "run", "--", "sh", "-c", "kill -SEGV $$")
	if code != 139 {
		t.Fatalf("passthrough code=%d, want 139", code)
	}
	if !strings.Contains(errOut, "SIGSEGV") {
		t.Errorf("diagnosis:\n%s", errOut)
	}
}

func TestRunJSONVerdictOnStderr(t *testing.T) {
	code, out, errOut := runCLI(t, "run", "--json", "--", "sh", "-c", "echo data; exit 3")
	if code != 3 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(out, "data") {
		t.Error("child stdout must stay clean of JSON")
	}
	data := decodeEnvelope(t, errOut, "verdict")
	if data["cause"] != "exit-code" {
		t.Errorf("payload = %v", data)
	}
}

func TestRunCommandNotFoundExits127(t *testing.T) {
	code, _, errOut := runCLI(t, "run", "--", "definitely-not-a-real-binary-4711")
	if code != 127 {
		t.Fatalf("code=%d, want 127", code)
	}
	if !strings.Contains(errOut, "127") {
		t.Errorf("stderr should explain the 127 convention:\n%s", errOut)
	}
}

func TestRunArgumentBoundary(t *testing.T) {
	// No command is a usage error; everything after -- belongs to the
	// child, including flag-like arguments.
	if code, _, _ := runCLI(t, "run"); code != ExitUsage {
		t.Error("run with no command should exit 2")
	}
	if code, _, _ := runCLI(t, "run", "--json"); code != ExitUsage {
		t.Error("run with only flags should exit 2")
	}
	code, out, _ := runCLI(t, "run", "--", "sh", "-c", "echo --json; exit 0")
	if code != 0 || !strings.Contains(out, "--json") {
		t.Errorf("child arguments were consumed: code=%d out=%q", code, out)
	}
}

func TestNegativeCodeReachesRangeExplanation(t *testing.T) {
	// "-1" must be treated as a positional, not a flag, so the user gets
	// the knowledge base's out-of-range explanation instead of a raw
	// flag-parse error — this is the tool people paste `echo $?` into.
	code, _, errOut := runCLI(t, "code", "-1")
	if code != ExitUsage || !strings.Contains(errOut, "8 bits") {
		t.Errorf("code=%d stderr=%q", code, errOut)
	}
	if strings.Contains(errOut, "flag provided") {
		t.Error("-1 must not be parsed as a flag")
	}
}

func TestScanSummaryUsesSingularForms(t *testing.T) {
	// A log with exactly one death must read "1 event, 1 process death".
	dir := t.TempDir()
	log := filepath.Join(dir, "one.log")
	line := "[1.000000] Out of memory: Killed process 7 (tiny) total-vm:8kB, anon-rss:4kB, file-rss:0kB, shmem-rss:0kB\n"
	if err := os.WriteFile(log, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runCLI(t, "scan", "--kmsg", log)
	if code != ExitOK || !strings.Contains(out, "whydied scan: 1 event, 1 process death\n") {
		t.Errorf("code=%d out=%q", code, out)
	}
}

func TestSignalWithoutConventionalNameRendersOnce(t *testing.T) {
	// glibc-reserved 32/33 have no SIG* name; the label must not
	// degenerate into "signal 32 (signal 32)".
	code, out, _ := runCLI(t, "signal", "32")
	if code != ExitOK {
		t.Fatal("signal 32 lookup failed")
	}
	if strings.Contains(out, "signal 32 (signal 32)") {
		t.Errorf("duplicated label:\n%s", out)
	}
	if !strings.Contains(out, "reserved by glibc") {
		t.Errorf("missing description:\n%s", out)
	}
}
