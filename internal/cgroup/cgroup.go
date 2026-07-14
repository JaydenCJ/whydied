// Package cgroup reads memory-controller evidence from a cgroup
// directory: the oom_kill counter that proves a kill happened, and the
// limit/peak/current numbers that show how close to the wall a workload
// ran. It understands both the v2 unified hierarchy (memory.events,
// memory.max, memory.peak) and v1 (memory.oom_control,
// memory.limit_in_bytes, memory.max_usage_in_bytes). All parsing is pure
// string functions over file contents, so it is fully testable with fake
// directories.
package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Unlimited is the value used for "no limit configured" (v2 "max", or the
// v1 no-limit sentinel).
const Unlimited int64 = -1

// Unknown marks a metric the kernel or hierarchy did not expose
// (e.g. memory.peak arrived in Linux 5.19).
const Unknown int64 = -2

// v1NoLimit is what memory.limit_in_bytes reads when unset: PAGE_SIZE
// rounding of LLONG_MAX. Anything this large means "unlimited".
const v1NoLimit int64 = int64(1) << 60

// Snapshot is one point-in-time read of a cgroup's memory controller.
type Snapshot struct {
	Version int    `json:"version"` // 1 or 2
	Path    string `json:"path"`    // directory the snapshot came from
	// OOMKills is the memory.events oom_kill counter (v2) or the
	// oom_kill field of memory.oom_control (v1, kernel ≥4.13):
	// how many processes the kernel has killed in this cgroup.
	OOMKills int64 `json:"oom_kills"`
	// OOMEvents counts limit-hit events that invoked the OOM logic
	// (v2 "oom"); Unknown on v1.
	OOMEvents int64 `json:"oom_events"`
	// GroupKills counts whole-group kills (v2 "oom_group_kill",
	// kernel ≥5.17); Unknown when absent.
	GroupKills int64 `json:"group_kills"`
	// MaxBytes is the configured hard limit (Unlimited if none).
	MaxBytes int64 `json:"max_bytes"`
	// PeakBytes is the high-water mark (Unknown if the kernel does not
	// expose it).
	PeakBytes int64 `json:"peak_bytes"`
	// CurrentBytes is usage at snapshot time.
	CurrentBytes int64 `json:"current_bytes"`
	// FailCnt is the v1 allocation-failure counter; Unknown on v2.
	FailCnt int64 `json:"fail_cnt"`
}

// Read snapshots the memory controller in dir, auto-detecting v2
// (memory.events present) versus v1 (memory.oom_control present).
func Read(dir string) (Snapshot, error) {
	if content, err := os.ReadFile(filepath.Join(dir, "memory.events")); err == nil {
		return readV2(dir, string(content)), nil
	}
	if content, err := os.ReadFile(filepath.Join(dir, "memory.oom_control")); err == nil {
		return readV1(dir, string(content)), nil
	}
	return Snapshot{}, fmt.Errorf("%s: neither memory.events (cgroup v2) nor memory.oom_control (v1) is readable — not a memory cgroup directory?", dir)
}

func readV2(dir, events string) Snapshot {
	ev := ParseKeyedCounters(events)
	s := Snapshot{
		Version:    2,
		Path:       dir,
		OOMKills:   counterOr(ev, "oom_kill", 0),
		OOMEvents:  counterOr(ev, "oom", 0),
		GroupKills: counterOr(ev, "oom_group_kill", Unknown),
		MaxBytes:   readBytesFile(filepath.Join(dir, "memory.max")),
		PeakBytes:  readBytesFile(filepath.Join(dir, "memory.peak")),
		FailCnt:    Unknown,
	}
	s.CurrentBytes = readBytesFile(filepath.Join(dir, "memory.current"))
	return s
}

func readV1(dir, oomControl string) Snapshot {
	ctl := ParseKeyedCounters(oomControl)
	s := Snapshot{
		Version:    1,
		Path:       dir,
		OOMKills:   counterOr(ctl, "oom_kill", Unknown), // absent before 4.13
		OOMEvents:  Unknown,
		GroupKills: Unknown,
		MaxBytes:   readBytesFile(filepath.Join(dir, "memory.limit_in_bytes")),
		PeakBytes:  readBytesFile(filepath.Join(dir, "memory.max_usage_in_bytes")),
		FailCnt:    readBytesFile(filepath.Join(dir, "memory.failcnt")),
	}
	if s.MaxBytes >= v1NoLimit {
		s.MaxBytes = Unlimited
	}
	s.CurrentBytes = readBytesFile(filepath.Join(dir, "memory.usage_in_bytes"))
	return s
}

// ParseKeyedCounters parses "key value" per-line files such as
// memory.events and memory.oom_control.
func ParseKeyedCounters(content string) map[string]int64 {
	out := make(map[string]int64)
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if n, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
			out[fields[0]] = n
		}
	}
	return out
}

func counterOr(m map[string]int64, key string, missing int64) int64 {
	if v, ok := m[key]; ok {
		return v
	}
	return missing
}

// ParseBytes parses a single-value memory file: a byte count, or the v2
// literal "max" meaning unlimited.
func ParseBytes(content string) (int64, error) {
	t := strings.TrimSpace(content)
	if t == "max" {
		return Unlimited, nil
	}
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("not a byte count: %q", t)
	}
	return n, nil
}

func readBytesFile(path string) int64 {
	content, err := os.ReadFile(path)
	if err != nil {
		return Unknown
	}
	n, err := ParseBytes(string(content))
	if err != nil {
		return Unknown
	}
	return n
}

// SelfPath extracts this process's cgroup path from /proc/self/cgroup
// content: the "0::" line on v2, or the memory controller line on v1.
// The returned path is relative to the cgroup mount root (starts with /).
func SelfPath(procSelfCgroup string) (path string, v2 bool, err error) {
	var v1Memory string
	for _, line := range strings.Split(procSelfCgroup, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			return parts[2], true, nil
		}
		for _, ctrl := range strings.Split(parts[1], ",") {
			if ctrl == "memory" {
				v1Memory = parts[2]
			}
		}
	}
	if v1Memory != "" {
		return v1Memory, false, nil
	}
	return "", false, fmt.Errorf("no v2 (0::) or v1 memory line in cgroup file")
}

// SelfDir resolves the calling process's own memory-cgroup directory on
// the standard /sys/fs/cgroup mount.
func SelfDir() (string, error) {
	content, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	rel, v2, err := SelfPath(string(content))
	if err != nil {
		return "", err
	}
	if v2 {
		return filepath.Join("/sys/fs/cgroup", rel), nil
	}
	return filepath.Join("/sys/fs/cgroup/memory", rel), nil
}

// NearLimit reports whether the snapshot shows usage brushing the
// configured limit: peak (preferred) or current within 2% of max. This is
// the "circumstantial evidence" tier when no kernel log is available.
func (s Snapshot) NearLimit() bool {
	if s.MaxBytes <= 0 {
		return false
	}
	probe := s.PeakBytes
	if probe < 0 {
		probe = s.CurrentBytes
	}
	if probe < 0 {
		return false
	}
	return probe >= s.MaxBytes-s.MaxBytes/50
}

// FormatBytes renders a byte count for humans (binary units), and the
// Unlimited/Unknown sentinels as words.
func FormatBytes(n int64) string {
	switch {
	case n == Unlimited:
		return "unlimited"
	case n < 0:
		return "unknown"
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	v := float64(n)
	for i, u := range units {
		v /= 1024
		if v < 1024 || i == len(units)-1 {
			return fmt.Sprintf("%.1f %s", v, u)
		}
	}
	return fmt.Sprintf("%d B", n) // unreachable
}
