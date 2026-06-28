// Package blocker tracks offenses per IP over a sliding window and decides
// how long an offender should be banned.
package blocker

import (
	"sync"
	"time"

	"code.sadeq.uk/simple-blocker/internal/config"
)

// Tracker records offenses per IP within a sliding time window and maps the
// resulting count onto a ban duration via the configured schedule.
//
// Tracker is safe for concurrent use.
type Tracker struct {
	window   time.Duration
	schedule config.BanSchedule
	now      func() time.Time // injectable clock for tests

	mu       sync.Mutex
	offenses map[string][]time.Time
}

// NewTracker creates a Tracker with the given window and ban schedule.
func NewTracker(window time.Duration, schedule config.BanSchedule) *Tracker {
	return &Tracker{
		window:   window,
		schedule: schedule,
		now:      time.Now,
		offenses: make(map[string][]time.Time),
	}
}

// Record registers a new offense for ip and returns the ban duration that
// applies given the number of offenses still inside the window. A zero
// duration means the offender has not yet crossed the lowest tier. The
// returned count is the current offense total within the window.
func (t *Tracker) Record(ip string) (ban time.Duration, count int) {
	now := t.now()
	cutoff := now.Add(-t.window)

	t.mu.Lock()
	defer t.mu.Unlock()

	kept := t.offenses[ip][:0]
	for _, ts := range t.offenses[ip] {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, now)
	t.offenses[ip] = kept

	count = len(kept)
	return t.schedule.DurationFor(count), count
}

// OffenseEntry is a per-IP view of the tracker: how many offenses fall inside
// the window right now, and the ban that count maps to.
type OffenseEntry struct {
	IP       string
	Count    int
	WouldBan time.Duration
}

// Snapshot returns the current in-window offense state per IP, without
// recording a new offense. It is read-only and safe for concurrent use.
func (t *Tracker) Snapshot() []OffenseEntry {
	cutoff := t.now().Add(-t.window)

	t.mu.Lock()
	defer t.mu.Unlock()

	out := make([]OffenseEntry, 0, len(t.offenses))
	for ip, stamps := range t.offenses {
		count := 0
		for _, ts := range stamps {
			if ts.After(cutoff) {
				count++
			}
		}
		if count == 0 {
			continue
		}
		out = append(out, OffenseEntry{
			IP:       ip,
			Count:    count,
			WouldBan: t.schedule.DurationFor(count),
		})
	}
	return out
}
