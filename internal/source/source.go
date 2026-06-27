// Package source tails log streams and reports offending IP addresses.
//
// Each Source wraps a long-running command (docker logs, journalctl) and
// applies a regular expression to every line. New source types only need to
// build a *exec.Cmd; the streaming, matching and retry logic is shared.
package source

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"time"

	"sadeq.uk/simple-blocker/internal/config"
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

// retryDelay is how long a source waits before restarting a failed command.
var retryDelay = 5 * time.Second

// New builds a Source from its configuration.
func New(c config.Source) (Source, error) {
	re, ipIdx, err := compilePattern(c.Pattern)
	if err != nil {
		return nil, fmt.Errorf("source %q: %w", label(c), err)
	}
	cs := &cmdSource{name: label(c), re: re, ipIdx: ipIdx}
	switch c.Type {
	case "docker":
		target := c.Target
		cs.build = func() *exec.Cmd {
			return exec.Command("docker", "logs", "-f", "--tail", "100", target)
		}
	case "journal":
		target, since := c.Target, c.Since
		cs.build = func() *exec.Cmd {
			return exec.Command("stdbuf", "-oL", "journalctl", "-af", "--since="+since, "-u", target)
		}
	default:
		return nil, fmt.Errorf("source %q: unknown type %q", label(c), c.Type)
	}
	return cs, nil
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

// cmdSource tails the output of a rebuilt command, matching each line.
type cmdSource struct {
	name  string
	re    *regexp.Regexp
	ipIdx int
	build func() *exec.Cmd
}

func (s *cmdSource) Name() string { return s.name }

func (s *cmdSource) Run(ctx context.Context, report Reporter) error {
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

// stream runs one instance of the command, scanning until it exits or ctx is
// cancelled.
func (s *cmdSource) stream(ctx context.Context, report Reporter) error {
	cmd := s.build()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return err
	}
	// Ensure the child is killed when ctx is cancelled so Wait returns.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
		case <-done:
		}
	}()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if m := s.re.FindStringSubmatch(scanner.Text()); m != nil && s.ipIdx < len(m) {
			report(m[s.ipIdx], s.name)
		}
	}
	werr := cmd.Wait()
	if ctx.Err() != nil {
		return nil // expected: we killed it
	}
	if serr := scanner.Err(); serr != nil {
		return serr
	}
	return werr
}
