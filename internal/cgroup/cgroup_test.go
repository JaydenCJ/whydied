// Tests for the cgroup evidence reader: v2 and v1 layouts built as fake
// directories in t.TempDir(), the parsing primitives, sentinel handling
// for absent files, and the near-limit heuristic.
package cgroup

import (
	"os"
	"path/filepath"
	"testing"
)

// writeCgroup creates a fake cgroup directory from a name→content map.
func writeCgroup(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestReadV2FullyPopulated(t *testing.T) {
	dir := writeCgroup(t, map[string]string{
		"memory.events":  "low 0\nhigh 12\nmax 340\noom 3\noom_kill 2\noom_group_kill 1\n",
		"memory.max":     "536870912\n",
		"memory.peak":    "536870912\n",
		"memory.current": "104857600\n",
	})
	s, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != 2 || s.OOMKills != 2 || s.OOMEvents != 3 || s.GroupKills != 1 {
		t.Errorf("snapshot = %+v", s)
	}
	if s.MaxBytes != 536870912 || s.PeakBytes != 536870912 || s.CurrentBytes != 104857600 {
		t.Errorf("byte fields = %+v", s)
	}
	if s.FailCnt != Unknown {
		t.Error("v1-only failcnt must read Unknown on v2")
	}
}

func TestReadV2UnlimitedAndMissingPeak(t *testing.T) {
	// memory.peak only exists on kernels ≥5.19; "max" means no limit.
	dir := writeCgroup(t, map[string]string{
		"memory.events":  "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
		"memory.max":     "max\n",
		"memory.current": "1024\n",
	})
	s, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.MaxBytes != Unlimited {
		t.Errorf("MaxBytes = %d, want Unlimited", s.MaxBytes)
	}
	if s.PeakBytes != Unknown {
		t.Errorf("PeakBytes = %d, want Unknown", s.PeakBytes)
	}
	if s.GroupKills != Unknown {
		t.Errorf("GroupKills = %d, want Unknown (pre-5.17 file)", s.GroupKills)
	}
}

func TestReadV1Layout(t *testing.T) {
	dir := writeCgroup(t, map[string]string{
		"memory.oom_control":        "oom_kill_disable 0\nunder_oom 0\noom_kill 4\n",
		"memory.limit_in_bytes":     "268435456\n",
		"memory.max_usage_in_bytes": "268435456\n",
		"memory.usage_in_bytes":     "134217728\n",
		"memory.failcnt":            "8121\n",
	})
	s, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != 1 || s.OOMKills != 4 || s.FailCnt != 8121 {
		t.Errorf("snapshot = %+v", s)
	}
	if s.MaxBytes != 268435456 || s.PeakBytes != 268435456 {
		t.Errorf("byte fields = %+v", s)
	}
}

func TestReadV1EdgeCases(t *testing.T) {
	// An unset v1 limit reads as a page-rounded LLONG_MAX and must
	// normalize to Unlimited, not look like an 8-EiB limit; kernels
	// before 4.13 have no oom_kill counter in oom_control at all.
	dir := writeCgroup(t, map[string]string{
		"memory.oom_control":    "oom_kill_disable 0\nunder_oom 0\noom_kill 0\n",
		"memory.limit_in_bytes": "9223372036854771712\n",
	})
	s, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.MaxBytes != Unlimited {
		t.Errorf("MaxBytes = %d, want Unlimited", s.MaxBytes)
	}
	dir = writeCgroup(t, map[string]string{
		"memory.oom_control": "oom_kill_disable 0\nunder_oom 0\n",
	})
	if s, err = Read(dir); err != nil {
		t.Fatal(err)
	}
	if s.OOMKills != Unknown {
		t.Errorf("OOMKills = %d, want Unknown", s.OOMKills)
	}
}

func TestReadRejectsNonCgroupDir(t *testing.T) {
	if _, err := Read(t.TempDir()); err == nil {
		t.Error("Read on an empty dir should fail with a diagnosis")
	}
}

func TestParseKeyedCountersSkipsMalformedLines(t *testing.T) {
	m := ParseKeyedCounters("oom 3\ngarbage\ntoo many fields here\noom_kill 1\nbad_value x\n")
	if m["oom"] != 3 || m["oom_kill"] != 1 {
		t.Errorf("m = %v", m)
	}
	if _, ok := m["bad_value"]; ok {
		t.Error("non-numeric value should be skipped")
	}
}

func TestParseBytes(t *testing.T) {
	if n, err := ParseBytes(" 4096\n"); err != nil || n != 4096 {
		t.Errorf("ParseBytes(4096) = %d, %v", n, err)
	}
	if n, err := ParseBytes("max\n"); err != nil || n != Unlimited {
		t.Errorf("ParseBytes(max) = %d, %v", n, err)
	}
	if _, err := ParseBytes("lots"); err == nil {
		t.Error("garbage should not parse")
	}
}

func TestSelfPathV2(t *testing.T) {
	path, v2, err := SelfPath("0::/user.slice/user-1000.slice/session-3.scope\n")
	if err != nil || !v2 || path != "/user.slice/user-1000.slice/session-3.scope" {
		t.Errorf("SelfPath = %q v2=%v err=%v", path, v2, err)
	}
}

func TestSelfPathV1PicksMemoryController(t *testing.T) {
	content := "12:pids:/init.scope\n4:memory:/system.slice/app.service\n2:cpu,cpuacct:/\n"
	path, v2, err := SelfPath(content)
	if err != nil || v2 || path != "/system.slice/app.service" {
		t.Errorf("SelfPath = %q v2=%v err=%v", path, v2, err)
	}
	// Combined controller lists must match too.
	path, _, err = SelfPath("3:cpuset,memory:/box\n")
	if err != nil || path != "/box" {
		t.Errorf("combined controllers: %q %v", path, err)
	}
	// And a file without any memory controller line must fail.
	if _, _, err := SelfPath("2:cpu:/\n"); err == nil {
		t.Error("cgroup file without memory controller should fail")
	}
}

func TestNearLimitHeuristic(t *testing.T) {
	near := Snapshot{MaxBytes: 1000, PeakBytes: 995}
	if !near.NearLimit() {
		t.Error("peak at 99.5% of max is near the limit")
	}
	far := Snapshot{MaxBytes: 1000, PeakBytes: 500}
	if far.NearLimit() {
		t.Error("peak at 50% is not near the limit")
	}
	// No limit → never "near".
	if (Snapshot{MaxBytes: Unlimited, PeakBytes: 1 << 40}).NearLimit() {
		t.Error("unlimited cgroup cannot be near its limit")
	}
	// Falls back to current when peak is unknown.
	cur := Snapshot{MaxBytes: 1000, PeakBytes: Unknown, CurrentBytes: 999}
	if !cur.NearLimit() {
		t.Error("current at 99.9% should count when peak is unavailable")
	}
}

func TestFormatBytes(t *testing.T) {
	cases := map[int64]string{
		Unlimited:  "unlimited",
		Unknown:    "unknown",
		512:        "512 B",
		536870912:  "512.0 MiB",
		1024:       "1.0 KiB",
		1073741824: "1.0 GiB",
	}
	for n, want := range cases {
		if got := FormatBytes(n); got != want {
			t.Errorf("FormatBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
