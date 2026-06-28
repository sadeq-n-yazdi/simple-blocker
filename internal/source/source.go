// Package source tails log streams and reports offending IP addresses.
//
// Each Source wraps a long-running byte stream (docker logs, journalctl, or the
// Docker Engine API) and applies a regular expression to every line. New source
// types only need to supply an opener; the streaming, matching and retry logic
// is shared by streamSource.
package source

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"regexp"
	"sync"
	"time"

	"code.sadeq.uk/simple-blocker/internal/config"
)

// Reporter is called with the offending IP and the source name for each match.
type Reporter func(ip, source string)

// Source monitors a log stream until its context is cancelled.
type Source interface {
	// Name returns the human-readable label for this source.
	Name() string
	// Run streams the source, calling report for every matched line. It
	// returns when ctx is cancelled.
	Run(ctx context.Context, report Reporter) error
}

// retryDelay is how long a source waits before restarting a failed stream.
var retryDelay = 5 * time.Second

// frameMode controls how a stream's bytes are framed.
type frameMode int

const (
	rawFrame  frameMode = iota // plain text, no headers (exec sources, TTY containers)
	muxFrame                   // always Docker stdcopy 8-byte headers
	autoFrame                  // sniff the first bytes to decide (Docker API default)
)

// opener returns a fresh log byte stream bound to ctx. Closing the returned
// ReadCloser (or cancelling ctx) must unblock any in-flight Read.
type opener func(ctx context.Context) (io.ReadCloser, error)

// New builds a following Source from its configuration (the daemon's mode).
func New(c config.Source) (Source, error) {
	return newSource(c, true)
}

// newSource builds a source; follow=true streams continuously (the daemon),
// follow=false reads recent logs once and stops (the `check` command).
func newSource(c config.Source, follow bool) (*streamSource, error) {
	re, ipIdx, err := compilePattern(c.Pattern)
	if err != nil {
		return nil, fmt.Errorf("source %q: %w", label(c), err)
	}
	name := label(c)

	switch c.Type {
	case "docker":
		switch c.Mode {
		case "internal", "": // internal is the docker default
			sock := c.DockerHost
			if sock == "" {
				sock = defaultDockerSocket
			}
			return newDockerAPISource(name, sock, c.Target, re, ipIdx, follow), nil
		case "external":
			target := c.Target
			build := func() *exec.Cmd {
				name, args := dockerLogsCmd(target, follow)
				return exec.Command(name, args...)
			}
			return &streamSource{name: name, re: re, ipIdx: ipIdx, open: cmdOpener(build), demux: rawFrame}, nil
		default:
			return nil, fmt.Errorf("source %q: invalid mode %q for docker (use internal or external)", name, c.Mode)
		}
	case "journal":
		// journal is exec-only; internal is rejected at config.Validate, but
		// guard here too for direct New callers.
		if c.Mode == "internal" {
			return nil, fmt.Errorf("source %q: journal does not support internal mode", name)
		}
		target, since := c.Target, c.Since
		build := func() *exec.Cmd {
			name, args := journalCmd(target, since, follow)
			return exec.Command(name, args...)
		}
		return &streamSource{name: name, re: re, ipIdx: ipIdx, open: cmdOpener(build), demux: rawFrame}, nil
	default:
		return nil, fmt.Errorf("source %q: unknown type %q", name, c.Type)
	}
}

// dockerLogsCmd builds the `docker logs` argv. Following adds -f; otherwise it
// reads recent history and exits.
func dockerLogsCmd(target string, follow bool) (string, []string) {
	args := []string{"logs", "--tail", "100"}
	if follow {
		args = append(args, "-f")
	}
	return "docker", append(args, target)
}

// journalCmd builds the journalctl argv. Following uses stdbuf+`-af` for live
// line-buffered output; otherwise it reads since the cutoff and exits.
func journalCmd(unit, since string, follow bool) (string, []string) {
	if follow {
		return "stdbuf", []string{"-oL", "journalctl", "-af", "--since=" + since, "-u", unit}
	}
	return "journalctl", []string{"--no-pager", "--since=" + since, "-u", unit}
}

// Match is one log line that matched a source's pattern. IPStart/IPEnd index
// the captured IP within Line (for highlighting); both are -1 if the IP group
// did not participate.
type Match struct {
	Source  string
	Line    string
	IP      string
	IPStart int
	IPEnd   int
}

// Scan reads a source once (follow=false) or continuously (follow=true) and
// calls onMatch for every line matching the pattern. It returns when the
// stream ends (finite read) or ctx is cancelled. Nothing is banned.
func Scan(ctx context.Context, c config.Source, follow bool, onMatch func(Match)) error {
	s, err := newSource(c, follow)
	if err != nil {
		return err
	}
	cb := func(line string, ipStart, ipEnd int) {
		m := Match{Source: s.name, Line: line, IPStart: ipStart, IPEnd: ipEnd}
		if ipStart >= 0 && ipEnd >= 0 {
			m.IP = line[ipStart:ipEnd]
		}
		onMatch(m)
	}
	if follow {
		return s.runLoop(ctx, cb)
	}
	return s.stream(ctx, cb)
}

func label(c config.Source) string {
	if c.Name != "" {
		return c.Name
	}
	return c.Target
}

// compilePattern compiles the regex and returns the submatch index of the
// "ip" named group, falling back to the first capturing group.
func compilePattern(pattern string) (*regexp.Regexp, int, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, 0, err
	}
	idx := 1
	for i, name := range re.SubexpNames() {
		if name == "ip" {
			idx = i
		}
	}
	if re.NumSubexp() < 1 {
		return nil, 0, fmt.Errorf("pattern must contain a capturing group for the IP")
	}
	return re, idx, nil
}

// streamSource owns the shared scan/match/retry/cancel logic. Concrete sources
// supply an opener and a frameMode.
type streamSource struct {
	name  string
	re    *regexp.Regexp
	ipIdx int
	open  opener
	demux frameMode
}

func (s *streamSource) Name() string { return s.name }

// matchFunc is called for each matching line with the line and the byte span
// of the captured IP within it.
type matchFunc func(line string, ipStart, ipEnd int)

func (s *streamSource) Run(ctx context.Context, report Reporter) error {
	return s.runLoop(ctx, func(line string, a, b int) {
		if a >= 0 && b >= 0 {
			report(line[a:b], s.name)
		}
	})
}

// runLoop streams with retry/backoff until ctx is cancelled (following mode).
func (s *streamSource) runLoop(ctx context.Context, onMatch matchFunc) error {
	for ctx.Err() == nil {
		if err := s.stream(ctx, onMatch); err != nil && ctx.Err() == nil {
			slog.Error("source failed, retrying", "source", s.name, "err", err, "in", retryDelay)
			select {
			case <-ctx.Done():
			case <-time.After(retryDelay):
			}
		}
	}
	return ctx.Err()
}

// stream opens one instance of the byte stream and scans it until it ends or
// ctx is cancelled, invoking onMatch per matching line.
func (s *streamSource) stream(ctx context.Context, onMatch matchFunc) error {
	rc, err := s.open(ctx)
	if err != nil {
		return err
	}
	defer rc.Close()

	// Closing the stream on cancel unblocks a blocked Read so the scan returns.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = rc.Close()
		case <-done:
		}
	}()

	br := bufio.NewReaderSize(rc, 64*1024)
	var r io.Reader = br
	if s.demux == muxFrame || (s.demux == autoFrame && needsDemux(br)) {
		r = newStdDemuxReader(br)
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		loc := s.re.FindStringSubmatchIndex(line)
		if loc == nil {
			continue
		}
		ipStart, ipEnd := -1, -1
		if 2*s.ipIdx+1 < len(loc) {
			ipStart, ipEnd = loc[2*s.ipIdx], loc[2*s.ipIdx+1]
		}
		onMatch(line, ipStart, ipEnd)
	}
	if ctx.Err() != nil {
		return nil // expected: we closed the stream
	}
	return scanner.Err()
}

// cmdStream wraps a running command as an io.ReadCloser whose Close kills the
// process and waits for it to reap. Close is idempotent: stream() may call it
// from both its cancel goroutine and its defer, but cmd.Wait must run once.
type cmdStream struct {
	cmd    *exec.Cmd
	stdout io.ReadCloser
	once   sync.Once
	werr   error
}

func (c *cmdStream) Read(p []byte) (int, error) { return c.stdout.Read(p) }

func (c *cmdStream) Close() error {
	c.once.Do(func() {
		if c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
		}
		_ = c.stdout.Close()
		c.werr = c.cmd.Wait()
	})
	return c.werr
}

// cmdOpener builds an opener that runs a command and streams its stdout.
func cmdOpener(build func() *exec.Cmd) opener {
	return func(ctx context.Context) (io.ReadCloser, error) {
		cmd := build()
		cmd.Stderr = nil
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, err
		}
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		return &cmdStream{cmd: cmd, stdout: stdout}, nil
	}
}
