package source

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"code.sadeq.uk/simple-blocker/internal/config"
)

// shortPoll speeds up the follow loop for tests and restores it on cleanup.
func shortPoll(t *testing.T) {
	t.Helper()
	prev := filePollInterval
	filePollInterval = 5 * time.Millisecond
	t.Cleanup(func() { filePollInterval = prev })
}

// collector gathers reported IPs in a goroutine-safe way.
type collector struct {
	mu  sync.Mutex
	ips []string
}

func (c *collector) add(m Match) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ips = append(c.ips, m.IP)
}

func (c *collector) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.ips...)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func appendFile(t *testing.T, path, content string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open append %s: %v", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("append %s: %v", path, err)
	}
}

// waitFor polls until cond is true or the deadline passes.
func waitFor(t *testing.T, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

const ipPattern = `(?P<ip>\d{1,3}(?:\.\d{1,3}){3})`

func TestFileSourceFiniteRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	writeFile(t, path,
		"hit from 10.0.0.1 here\nnothing\nhit from 10.0.0.2 here\n")

	c := config.Source{Type: "file", Name: "f", Target: path, Pattern: `from ` + ipPattern}
	var got collector
	if err := Scan(context.Background(), c, false, got.add); err != nil {
		t.Fatalf("scan: %v", err)
	}
	ips := got.snapshot()
	if len(ips) != 2 || ips[0] != "10.0.0.1" || ips[1] != "10.0.0.2" {
		t.Fatalf("unexpected matches: %v", ips)
	}
}

func TestFileSourceFollowAppend(t *testing.T) {
	shortPoll(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeFile(t, path, "from 10.0.0.1 first\n")

	ctx, cancel := context.WithCancel(context.Background())
	c := config.Source{Type: "file", Name: "f", Target: path, Pattern: `from ` + ipPattern}
	var got collector
	done := make(chan struct{})
	go func() { _ = Scan(ctx, c, true, got.add); close(done) }()

	// Pre-existing line is read from the start.
	if !waitFor(t, func() bool { return len(got.snapshot()) == 1 }) {
		t.Fatalf("did not read initial line: %v", got.snapshot())
	}
	appendFile(t, path, "from 10.0.0.2 second\n")
	if !waitFor(t, func() bool { return len(got.snapshot()) == 2 }) {
		t.Fatalf("did not pick up appended line: %v", got.snapshot())
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not return promptly after cancel")
	}
	ips := got.snapshot()
	if ips[0] != "10.0.0.1" || ips[1] != "10.0.0.2" {
		t.Fatalf("unexpected order: %v", ips)
	}
}

func TestFileSourceFollowTruncate(t *testing.T) {
	shortPoll(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeFile(t, path, "from 10.0.0.1 first\n")

	ctx, cancel := context.WithCancel(context.Background())
	c := config.Source{Type: "file", Name: "f", Target: path, Pattern: `from ` + ipPattern}
	var got collector
	done := make(chan struct{})
	go func() { _ = Scan(ctx, c, true, got.add); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	if !waitFor(t, func() bool { return len(got.snapshot()) == 1 }) {
		t.Fatalf("initial: %v", got.snapshot())
	}
	// Truncate (copytruncate style) then write fresh content. Give the follower
	// a moment to observe the empty file before regrowth — polling-based
	// detection needs to see size < offset (as it would with a real logger that
	// truncates, then appends over time).
	writeFile(t, path, "")
	if !waitFor(t, func() bool {
		fi, err := os.Stat(path)
		return err == nil && fi.Size() == 0
	}) {
		t.Fatal("file not observed empty")
	}
	time.Sleep(3 * filePollInterval)
	appendFile(t, path, "from 10.0.0.9 after-trunc\n")
	if !waitFor(t, func() bool {
		ips := got.snapshot()
		return len(ips) == 2 && ips[1] == "10.0.0.9"
	}) {
		t.Fatalf("did not read post-truncate line: %v", got.snapshot())
	}
}

func TestFileSourceFollowRotate(t *testing.T) {
	shortPoll(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	writeFile(t, path, "from 10.0.0.1 first\n")

	ctx, cancel := context.WithCancel(context.Background())
	c := config.Source{Type: "file", Name: "f", Target: path, Pattern: `from ` + ipPattern}
	var got collector
	done := make(chan struct{})
	go func() { _ = Scan(ctx, c, true, got.add); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	if !waitFor(t, func() bool { return len(got.snapshot()) == 1 }) {
		t.Fatalf("initial: %v", got.snapshot())
	}
	// Rotate: rename the live file away and create a fresh one at the path.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatalf("rotate rename: %v", err)
	}
	writeFile(t, path, "from 10.0.0.7 rotated\n")
	if !waitFor(t, func() bool {
		ips := got.snapshot()
		return len(ips) == 2 && ips[1] == "10.0.0.7"
	}) {
		t.Fatalf("did not read rotated file: %v", got.snapshot())
	}
}

func TestFileSourceTimeWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	now := time.Now()
	old := now.Add(-3 * time.Hour).Format("02/Jan/2006:15:04:05 -0700")
	recent := now.Add(-1 * time.Minute).Format("02/Jan/2006:15:04:05 -0700")
	writeFile(t, path, fmt.Sprintf(
		"1.1.1.1 - [%s] hit\n2.2.2.2 - [%s] hit\n", old, recent))

	c := config.Source{
		Type: "file", Name: "f", Target: path, Since: "-1h",
		Pattern: `(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - \[(?P<ts>[^\]]+)\]`,
	}
	var got collector
	if err := Scan(context.Background(), c, false, got.add); err != nil {
		t.Fatalf("scan: %v", err)
	}
	ips := got.snapshot()
	if len(ips) != 1 || ips[0] != "2.2.2.2" {
		t.Fatalf("expected only the recent line, got: %v", ips)
	}
}

func TestFileSourceUnparseableTSSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	writeFile(t, path, "1.1.1.1 - [not-a-date] hit\n")

	c := config.Source{
		Type: "file", Name: "f", Target: path, Since: "-1h",
		Pattern: `(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - \[(?P<ts>[^\]]+)\]`,
	}
	var got collector
	if err := Scan(context.Background(), c, false, got.add); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if ips := got.snapshot(); len(ips) != 0 {
		t.Fatalf("fail-closed: expected no matches, got: %v", ips)
	}
}

func TestFileSourceNoTSReadsAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	old := time.Now().Add(-72 * time.Hour).Format("02/Jan/2006:15:04:05 -0700")
	writeFile(t, path, fmt.Sprintf("from 9.9.9.9 [%s]\n", old))

	// No (?P<ts>) group: time filtering is disabled, the line is reported even
	// though it is ancient.
	c := config.Source{Type: "file", Name: "f", Target: path, Since: "-1h", Pattern: `from ` + ipPattern}
	var got collector
	if err := Scan(context.Background(), c, false, got.add); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if ips := got.snapshot(); len(ips) != 1 || ips[0] != "9.9.9.9" {
		t.Fatalf("expected the line read, got: %v", ips)
	}
}

func TestFileSourceMissingFileErrors(t *testing.T) {
	c := config.Source{Type: "file", Name: "f", Target: filepath.Join(t.TempDir(), "nope.log"), Pattern: `from ` + ipPattern}
	// Finite read of a missing file surfaces the open error.
	if err := Scan(context.Background(), c, false, func(Match) {}); err == nil {
		t.Fatal("expected an error opening a missing file")
	}
}

func TestParseTS(t *testing.T) {
	now := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		in   string
		want bool
	}{
		{"28/Jun/2026:11:59:00 +0000", true}, // nginx
		{"2026-06-28T11:59:00Z", true},       // RFC3339
		{"2026-06-28 11:59:00", true},        // app log
		{"garbage", false},
	}
	for _, tc := range cases {
		_, ok := parseTS(tc.in, builtinTSLayouts, now)
		if ok != tc.want {
			t.Errorf("parseTS(%q) ok=%v, want %v", tc.in, ok, tc.want)
		}
	}

	// Yearless syslog timestamps are filled with a sensible year (near now).
	got, ok := parseTS("Jun 28 11:59:00", builtinTSLayouts, now)
	if !ok {
		t.Fatal("expected yearless syslog to parse")
	}
	if got.Year() != 2026 {
		t.Errorf("yearless fill: year=%d, want 2026", got.Year())
	}
}

func TestSinceCutoff(t *testing.T) {
	now := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	if got := sinceCutoff("-1d", now); !got.Equal(now.Add(-24 * time.Hour)) {
		t.Errorf("-1d cutoff = %v", got)
	}
	if got := sinceCutoff("12h", now); !got.Equal(now.Add(-12 * time.Hour)) {
		t.Errorf("12h cutoff = %v", got)
	}
	if got := sinceCutoff("garbage", now); !got.Equal(now) {
		t.Errorf("garbage should yield now, got %v", got)
	}
}
