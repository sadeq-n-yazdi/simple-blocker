package source

import (
	"context"
	"io"
	"regexp"
	"strings"
	"testing"
)

func mustRE(p string) *regexp.Regexp { return regexp.MustCompile(p) }

func fakeOpener(s string) opener {
	return func(ctx context.Context) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(s)), nil
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestDockerLogsCmd(t *testing.T) {
	name, args := dockerLogsCmd("web", false)
	if name != "docker" || strings.Contains(strings.Join(args, " "), "-f") {
		t.Errorf("finite docker args should omit -f: %v", args)
	}
	if args[len(args)-1] != "web" {
		t.Errorf("target should be last: %v", args)
	}
	_, fargs := dockerLogsCmd("web", true)
	if !contains(fargs, "-f") {
		t.Errorf("follow docker args should include -f: %v", fargs)
	}
}

func TestJournalCmd(t *testing.T) {
	name, args := journalCmd("ssh", "-1d", false)
	if name != "journalctl" {
		t.Errorf("finite journal should run journalctl directly, got %q", name)
	}
	if contains(args, "-af") || contains(args, "-f") {
		t.Errorf("finite journal args should not follow: %v", args)
	}
	if !contains(args, "--no-pager") {
		t.Errorf("finite journal should pass --no-pager: %v", args)
	}
	fname, fargs := journalCmd("ssh", "-1d", true)
	if fname != "stdbuf" || !contains(fargs, "-af") {
		t.Errorf("follow journal should be stdbuf … -af: %q %v", fname, fargs)
	}
}

// TestScanMatchSpans drives streamSource.stream (which Scan wraps) through a
// fake opener and checks the Match line + IP span are correct.
func TestScanMatchSpans(t *testing.T) {
	lines := "Invalid user a from 10.0.0.1 port 22\nnothing here\nfrom 10.0.0.2 now\n"
	s := &streamSource{
		name:  "fake",
		re:    mustRE(`from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})`),
		ipIdx: 1,
		open:  fakeOpener(lines),
		demux: rawFrame,
	}
	var matches []Match
	cb := func(line string, a, b int) {
		m := Match{Source: s.name, Line: line, IPStart: a, IPEnd: b}
		if a >= 0 {
			m.IP = line[a:b]
		}
		matches = append(matches, m)
	}
	if err := s.stream(context.Background(), cb); err != nil {
		t.Fatalf("stream: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d: %+v", len(matches), matches)
	}
	if matches[0].IP != "10.0.0.1" || matches[0].Line[matches[0].IPStart:matches[0].IPEnd] != "10.0.0.1" {
		t.Errorf("match0 span wrong: %+v", matches[0])
	}
	if matches[1].IP != "10.0.0.2" {
		t.Errorf("match1 ip wrong: %+v", matches[1])
	}
}
