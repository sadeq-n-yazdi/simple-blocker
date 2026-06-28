package source

import (
	"context"
	"testing"
	"time"

	"code.sadeq.uk/simple-blocker/internal/config"
)

func TestCompilePatternNamedGroup(t *testing.T) {
	re, idx, err := compilePattern(`Invalid user \S+ from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	m := re.FindStringSubmatch("Invalid user admin from 10.0.0.5 port 22")
	if m == nil || m[idx] != "10.0.0.5" {
		t.Fatalf("got %v idx %d", m, idx)
	}
}

func TestCompilePatternFallbackToFirstGroup(t *testing.T) {
	// No named "ip" group: the first capturing group is used.
	re, idx, err := compilePattern(`from (\d+\.\d+\.\d+\.\d+)`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if idx != 1 {
		t.Fatalf("idx = %d, want 1", idx)
	}
	m := re.FindStringSubmatch("from 1.2.3.4")
	if m[idx] != "1.2.3.4" {
		t.Fatalf("match = %q", m[idx])
	}
}

func TestCompilePatternRequiresGroup(t *testing.T) {
	if _, _, err := compilePattern(`no groups here`); err == nil {
		t.Fatal("expected error when pattern has no capturing group")
	}
}

func TestNewUnknownType(t *testing.T) {
	_, err := New(config.Source{Type: "syslog", Target: "x", Pattern: "(?P<ip>x)"})
	if err == nil {
		t.Fatal("expected error for unknown source type")
	}
}

func demuxOf(t *testing.T, s Source) frameMode {
	t.Helper()
	ss, ok := s.(*streamSource)
	if !ok {
		t.Fatalf("source is %T, not *streamSource", s)
	}
	return ss.demux
}

func TestNewDockerModeSelection(t *testing.T) {
	// Internal (and default empty) docker → API source (autoFrame).
	for _, mode := range []string{"internal", ""} {
		s, err := New(config.Source{Type: "docker", Mode: mode, Target: "c", Pattern: "(?P<ip>x)"})
		if err != nil {
			t.Fatalf("docker mode %q: %v", mode, err)
		}
		if demuxOf(t, s) != autoFrame {
			t.Errorf("docker mode %q: demux = %v, want autoFrame", mode, demuxOf(t, s))
		}
	}
	// External docker → exec source (rawFrame).
	s, err := New(config.Source{Type: "docker", Mode: "external", Target: "c", Pattern: "(?P<ip>x)"})
	if err != nil {
		t.Fatalf("docker external: %v", err)
	}
	if demuxOf(t, s) != rawFrame {
		t.Errorf("docker external: demux = %v, want rawFrame", demuxOf(t, s))
	}
}

func TestNewDockerBadMode(t *testing.T) {
	_, err := New(config.Source{Type: "docker", Mode: "sideways", Target: "c", Pattern: "(?P<ip>x)"})
	if err == nil {
		t.Fatal("expected error for invalid docker mode")
	}
}

func TestNewJournalInternalRejected(t *testing.T) {
	_, err := New(config.Source{Type: "journal", Mode: "internal", Target: "ssh", Pattern: "(?P<ip>x)"})
	if err == nil {
		t.Fatal("expected error: journal does not support internal mode")
	}
}

func TestPHPProbePattern(t *testing.T) {
	// The example docker pattern should catch a 404 probe to a .php path.
	pattern := `(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s.*?"[A-Z]+\s+\S*\.(?:php|exe|xml|gz)\S*\s+HTTP/\d\.\d".*\s404\s`
	re, idx, err := compilePattern(pattern)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	line := `45.9.1.2 - - [01/Jan/2026:00:00:00 +0000] "GET /wp-login.php?x=1 HTTP/1.1" 404 200 "-" "bot"`
	m := re.FindStringSubmatch(line)
	if m == nil || m[idx] != "45.9.1.2" {
		t.Fatalf("expected match of 45.9.1.2, got %v", m)
	}
	// A normal 200 request must not match.
	if re.MatchString(`45.9.1.2 - - [..] "GET /index.html HTTP/1.1" 200 10 "-" "ua"`) {
		t.Fatal("should not match a normal 200 request")
	}
}

func TestRunHonorsContextCancel(t *testing.T) {
	// A docker source whose command will fail fast; Run must return promptly
	// once the context is cancelled rather than retrying forever.
	s, err := New(config.Source{Type: "journal", Target: "definitely-not-a-unit", Pattern: "(?P<ip>x)"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	old := retryDelay
	retryDelay = 10 * time.Millisecond
	defer func() { retryDelay = old }()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, func(string, string) {}) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}
