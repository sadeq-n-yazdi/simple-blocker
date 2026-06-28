package blocker

import (
	"testing"
	"time"
)

func TestSnapshot(t *testing.T) {
	now := time.Unix(10000, 0)
	tr := NewTracker(time.Hour, schedule()) // schedule(): 2→10m, 3→30m
	tr.now = func() time.Time { return now }

	tr.Record("1.1.1.1") // count 1 → would-ban 0
	tr.Record("2.2.2.2") // count 1
	tr.Record("2.2.2.2") // count 2 → would-ban 10m

	snap := tr.Snapshot()
	byIP := map[string]OffenseEntry{}
	for _, e := range snap {
		byIP[e.IP] = e
	}
	if byIP["1.1.1.1"].Count != 1 || byIP["1.1.1.1"].WouldBan != 0 {
		t.Errorf("1.1.1.1 = %+v", byIP["1.1.1.1"])
	}
	if byIP["2.2.2.2"].Count != 2 || byIP["2.2.2.2"].WouldBan != 10*time.Minute {
		t.Errorf("2.2.2.2 = %+v", byIP["2.2.2.2"])
	}
}

func TestSnapshotPrunesExpired(t *testing.T) {
	now := time.Unix(10000, 0)
	tr := NewTracker(time.Hour, schedule())
	tr.now = func() time.Time { return now }
	tr.Record("3.3.3.3")
	now = now.Add(2 * time.Hour) // age the offense out of the window
	snap := tr.Snapshot()
	for _, e := range snap {
		if e.IP == "3.3.3.3" {
			t.Fatalf("expected 3.3.3.3 pruned, got %+v", e)
		}
	}
	// Snapshot must also drop the stale key from the map (no slow leak).
	if _, ok := tr.offenses["3.3.3.3"]; ok {
		t.Fatal("expected 3.3.3.3 removed from offenses map after Snapshot")
	}
}
