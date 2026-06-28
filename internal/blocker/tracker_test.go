package blocker

import (
	"sync"
	"testing"
	"time"

	"code.sadeq.uk/simple-blocker/internal/config"
	"code.sadeq.uk/simple-blocker/internal/ipmatch"
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

// emptyLists returns two empty (match-nothing) matchers.
func emptyLists() (*ipmatch.List, *ipmatch.List) {
	w, _ := ipmatch.New(nil)
	b, _ := ipmatch.New(nil)
	return w, b
}

func mustList(t *testing.T, specs ...string) *ipmatch.List {
	t.Helper()
	l, err := ipmatch.New(specs)
	if err != nil {
		t.Fatalf("ipmatch.New(%v): %v", specs, err)
	}
	return l
}

func TestEngineBansOnlyWhenScheduled(t *testing.T) {
	fb := &fakeBanner{}
	w, b := emptyLists()
	e := NewEngine(NewTracker(time.Hour, schedule()), fb, w, b)
	e.Report("9.9.9.9", "ssh") // count 1: no ban
	if len(fb.bans) != 0 {
		t.Fatalf("expected no ban on first offense, got %d", len(fb.bans))
	}
	e.Report("9.9.9.9", "ssh") // count 2: 10m ban
	if len(fb.bans) != 1 || fb.bans[0].d != 10*time.Minute {
		t.Fatalf("expected one 10m ban, got %+v", fb.bans)
	}
}

func TestEngineWhitelistNeverBans(t *testing.T) {
	fb := &fakeBanner{}
	e := NewEngine(NewTracker(time.Hour, schedule()), fb, mustList(t, "9.9.9.0/24"), mustList(t))
	for i := 0; i < 5; i++ {
		e.Report("9.9.9.9", "ssh")
	}
	if len(fb.bans) != 0 {
		t.Fatalf("whitelisted IP was banned: %+v", fb.bans)
	}
}

func TestEngineBlacklistBansPermanently(t *testing.T) {
	fb := &fakeBanner{}
	e := NewEngine(NewTracker(time.Hour, schedule()), fb, mustList(t), mustList(t, "8.8.8.0/24"))
	e.Report("8.8.8.8", "ssh") // first sighting bans permanently
	if len(fb.bans) != 1 || fb.bans[0].d != 0 {
		t.Fatalf("expected one permanent (d=0) ban, got %+v", fb.bans)
	}
}

func TestEngineWhitelistWinsOverBlacklist(t *testing.T) {
	fb := &fakeBanner{}
	e := NewEngine(NewTracker(time.Hour, schedule()), fb, mustList(t, "7.7.7.7"), mustList(t, "7.7.7.7"))
	e.Report("7.7.7.7", "ssh")
	if len(fb.bans) != 0 {
		t.Fatalf("whitelist should win over blacklist, got %+v", fb.bans)
	}
}

func TestEngineSetListsSwap(t *testing.T) {
	fb := &fakeBanner{}
	w, b := emptyLists()
	e := NewEngine(NewTracker(time.Hour, schedule()), fb, w, b)
	e.Report("6.6.6.6", "ssh") // not listed: count 1, no ban
	if len(fb.bans) != 0 {
		t.Fatalf("unexpected ban before swap: %+v", fb.bans)
	}
	e.SetLists(mustList(t), mustList(t, "6.6.6.6")) // now blacklisted
	e.Report("6.6.6.6", "ssh")
	if len(fb.bans) != 1 || fb.bans[0].d != 0 {
		t.Fatalf("expected permanent ban after swap, got %+v", fb.bans)
	}
}

func TestEngineSkipsIPv6Enforcement(t *testing.T) {
	fb := &fakeBanner{}
	e := NewEngine(NewTracker(time.Hour, schedule()), fb, mustList(t), mustList(t, "2001:db8::/32"))
	e.Report("2001:db8::1", "ssh") // matches blacklist but can't be enforced
	if len(fb.bans) != 0 {
		t.Fatalf("v6 target should be skipped, not banned: %+v", fb.bans)
	}
}
