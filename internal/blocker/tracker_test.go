package blocker

import (
	"sync"
	"testing"
	"time"

	"sadeq.uk/simple-blocker/internal/config"
)

func schedule() config.BanSchedule {
	return config.BanSchedule{
		{Offenses: 2, Ban: config.Duration(10 * time.Minute)},
		{Offenses: 3, Ban: config.Duration(30 * time.Minute)},
	}
}

func TestRecordEscalates(t *testing.T) {
	now := time.Unix(1000, 0)
	tr := NewTracker(time.Hour, schedule())
	tr.now = func() time.Time { return now }

	if ban, count := tr.Record("1.1.1.1"); ban != 0 || count != 1 {
		t.Fatalf("first offense: ban=%v count=%d", ban, count)
	}
	if ban, count := tr.Record("1.1.1.1"); ban != 10*time.Minute || count != 2 {
		t.Fatalf("second offense: ban=%v count=%d", ban, count)
	}
	if ban, count := tr.Record("1.1.1.1"); ban != 30*time.Minute || count != 3 {
		t.Fatalf("third offense: ban=%v count=%d", ban, count)
	}
}

func TestRecordWindowExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	tr := NewTracker(time.Hour, schedule())
	tr.now = func() time.Time { return now }

	tr.Record("2.2.2.2") // count 1
	now = now.Add(90 * time.Minute)
	// The earlier offense is now outside the 1h window, so this is count 1.
	if ban, count := tr.Record("2.2.2.2"); ban != 0 || count != 1 {
		t.Fatalf("after expiry: ban=%v count=%d", ban, count)
	}
}

func TestRecordPerIPIsolation(t *testing.T) {
	tr := NewTracker(time.Hour, schedule())
	tr.Record("a")
	if _, count := tr.Record("b"); count != 1 {
		t.Fatalf("ip b should be independent, got count=%d", count)
	}
}

func TestRecordConcurrent(t *testing.T) {
	tr := NewTracker(time.Hour, schedule())
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); tr.Record("x") }()
	}
	wg.Wait()
	if _, count := tr.Record("x"); count != 101 {
		t.Fatalf("expected 101 offenses, got %d", count)
	}
}

// fakeBanner records the bans the engine applies.
type fakeBanner struct {
	mu   sync.Mutex
	bans []struct {
		ip string
		d  time.Duration
	}
}

func (f *fakeBanner) Ban(ip string, d time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bans = append(f.bans, struct {
		ip string
		d  time.Duration
	}{ip, d})
	return nil
}

func TestEngineBansOnlyWhenScheduled(t *testing.T) {
	fb := &fakeBanner{}
	e := NewEngine(NewTracker(time.Hour, schedule()), fb)
	e.Report("9.9.9.9", "ssh") // count 1: no ban
	if len(fb.bans) != 0 {
		t.Fatalf("expected no ban on first offense, got %d", len(fb.bans))
	}
	e.Report("9.9.9.9", "ssh") // count 2: 10m ban
	if len(fb.bans) != 1 || fb.bans[0].d != 10*time.Minute {
		t.Fatalf("expected one 10m ban, got %+v", fb.bans)
	}
}
