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

// New builds a Source from its configuration.
func New(c config.Source) (Source, error) {
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
			return newDockerAPISource(name, sock, c.Target, re, ipIdx), nil
		case "external":
			target := c.Target
			build := func() *exec.Cmd {
				return exec.Command("docker", "logs", "-f", "--tail", "100", target)
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
			return exec.Command("stdbuf", "-oL", "journalctl", "-af", "--since="+since, "-u", target)
		}
		return &streamSource{name: name, re: re, ipIdx: ipIdx, open: cmdOpener(build), demux: rawFrame}, nil
	default:
		return nil, fmt.Errorf("source %q: unknown type %q", name, c.Type)
	}
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

func (s *streamSource) Run(ctx context.Context, report Reporter) error {
	for ctx.Err() == nil {
		if err := s.stream(ctx, report); err != nil && ctx.Err() == nil {
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
// ctx is cancelled.
func (s *streamSource) stream(ctx context.Context, report Reporter) error {
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
		if m := s.re.FindStringSubmatch(scanner.Text()); m != nil && s.ipIdx < len(m) {
			report(m[s.ipIdx], s.name)
		}
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
