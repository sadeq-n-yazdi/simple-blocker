package source

import (
	"context"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// filePollInterval is how often a following file reader checks for new data or
// rotation once it has reached the end of the file.
var filePollInterval = 500 * time.Millisecond

// fileOpener tails a plain log file. follow=false opens it and reads to EOF once
// (the `check` command); follow=true reads from the start and then keeps
// following, handling rotation and truncation (the daemon). The file not
// existing yet is reported as an error so the caller's retry loop can wait for it.
func fileOpener(path string, follow bool) opener {
	return func(ctx context.Context) (io.ReadCloser, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		if !follow {
			return f, nil
		}
		return &followReader{path: path, f: f, stop: make(chan struct{})}, nil
	}
}

// followReader is an io.ReadCloser that implements `tail -F` semantics over the
// standard library: when it reaches EOF it polls for new data, follows the file
// across rotation (rename + recreate, detected via os.SameFile) and resets on
// truncation. Close unblocks an in-flight Read so the scan returns on cancel.
type followReader struct {
	path string

	mu  sync.Mutex // guards f and off (refresh reopens across rotation)
	f   *os.File
	off int64 // bytes read from the current file

	stop     chan struct{}
	closeOne sync.Once
}

func (r *followReader) Read(p []byte) (int, error) {
	for {
		r.mu.Lock()
		n, err := r.f.Read(p)
		if n > 0 {
			r.off += int64(n)
		}
		r.mu.Unlock()
		if n > 0 {
			return n, nil
		}
		if err != nil && err != io.EOF {
			return 0, err
		}
		// At EOF: wait for the file to grow, rotate, or for Close/cancel.
		select {
		case <-r.stop:
			return 0, io.EOF
		case <-time.After(filePollInterval):
		}
		r.mu.Lock()
		rerr := r.refresh()
		r.mu.Unlock()
		if rerr != nil {
			return 0, rerr
		}
	}
}

// refresh handles rotation and truncation. If the path now points at a different
// file (logrotate rename + recreate) it reopens from the start; if the current
// file shrank (copytruncate) it seeks back to the beginning. The caller holds r.mu.
func (r *followReader) refresh() error {
	pathInfo, err := os.Stat(r.path)
	if err != nil {
		// The path is gone (rotated away, not yet recreated). Keep the current
		// handle and wait; a later poll will pick up the replacement.
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	fInfo, err := r.f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(pathInfo, fInfo) {
		nf, err := os.Open(r.path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		_ = r.f.Close()
		r.f = nf
		r.off = 0
		return nil
	}
	// Truncation (copytruncate): the file shrank below where we've read to, so
	// restart from the beginning. This is best-effort — if a logger truncates and
	// regrows past our offset between two polls we can't tell it apart from normal
	// growth (the inherent race of polling-based copytruncate detection).
	if pathInfo.Size() < r.off {
		if _, err := r.f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		r.off = 0
	}
	return nil
}

func (r *followReader) Close() error {
	r.closeOne.Do(func() { close(r.stop) })
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

// builtinTSLayouts are the timestamp layouts a file source tries, in order, when
// a (?P<ts>...) capture is present and no explicit time_format is configured.
var builtinTSLayouts = []string{
	"02/Jan/2006:15:04:05 -0700", // nginx / Apache combined log
	time.RFC3339,                 // 2006-01-02T15:04:05Z07:00
	"2006-01-02T15:04:05",        // ISO 8601, no zone
	"2006-01-02 15:04:05",        // common app log
	time.RFC1123Z,
	time.RFC1123,
	"Jan _2 15:04:05", // syslog (yearless, space-padded day)
	"Jan 2 15:04:05",  // syslog (yearless)
}

// parseTS parses s against the given layouts, returning the first success. For
// yearless layouts (which Go parses with year 0) it fills in the year so the
// timestamp lands near now, backing off a year if that would put it more than a
// day in the future. ok is false if no layout matches.
func parseTS(s string, layouts []string, now time.Time) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range layouts {
		t, err := time.Parse(layout, s)
		if err != nil {
			continue
		}
		if t.Year() == 0 {
			t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
			if t.Sub(now) > 24*time.Hour {
				t = t.AddDate(-1, 0, 0)
			}
		}
		return t, true
	}
	return time.Time{}, false
}

// sinceCutoff converts a lookback spec into the oldest timestamp a file source
// accepts. It understands an optional leading '-' and a single unit suffix
// s/m/h/d (so the default "-1d" works, as does e.g. "12h"). If the spec is empty
// or unrecognized it returns now, i.e. no lines are old enough to skip beyond
// the present — callers treat that as "read everything from the cutoff onward".
func sinceCutoff(since string, now time.Time) time.Time {
	d, ok := parseLookback(since)
	if !ok {
		return now
	}
	return now.Add(-d)
}

// parseLookback parses specs like "-1d", "1d", "12h", "30m" into a positive
// duration. The leading '-' is optional and ignored (a lookback is always past).
func parseLookback(s string) (time.Duration, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "-")
	if s == "" {
		return 0, false
	}
	unit := s[len(s)-1]
	num := s[:len(s)-1]
	n, err := strconv.Atoi(num)
	if err != nil || n < 0 {
		return 0, false
	}
	switch unit {
	case 's':
		return time.Duration(n) * time.Second, true
	case 'm':
		return time.Duration(n) * time.Minute, true
	case 'h':
		return time.Duration(n) * time.Hour, true
	case 'd':
		return time.Duration(n) * 24 * time.Hour, true
	default:
		return 0, false
	}
}

// compile-time guard that followReader satisfies io.ReadCloser.
var _ io.ReadCloser = (*followReader)(nil)
