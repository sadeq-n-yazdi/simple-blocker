package control

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestServeAndDial(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "ctl.sock")
	want := Snapshot{
		Backend:   "nftables-native",
		Bans:      []Ban{{IP: "1.2.3.4", ExpiresSeconds: 59}},
		Offenders: []Offender{{IP: "5.6.7.8", Count: 2, WouldBanSeconds: 600}},
		TS:        "2026-06-28T00:00:00Z",
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, sock, func() (Snapshot, error) { return want, nil })

	// Wait for the listener to come up.
	var snap Snapshot
	var err error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snap, err = Dial(sock)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("Dial never succeeded: %v", err)
	}
	if snap.Backend != want.Backend || len(snap.Bans) != 1 || snap.Bans[0].IP != "1.2.3.4" {
		t.Fatalf("snapshot mismatch: %+v", snap)
	}
	if len(snap.Offenders) != 1 || snap.Offenders[0].Count != 2 {
		t.Fatalf("offenders mismatch: %+v", snap.Offenders)
	}
}

func TestDialNoServer(t *testing.T) {
	if _, err := Dial(filepath.Join(t.TempDir(), "absent.sock")); err == nil {
		t.Fatal("expected error dialing a missing socket")
	}
}

func TestServeBuildError(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "err.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, sock, func() (Snapshot, error) {
		return Snapshot{}, errBuild
	})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snap, err := Dial(sock)
		if err == nil {
			if snap.Error == "" {
				t.Fatal("expected snapshot.Error to be set")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("never connected")
}

type buildErr struct{}

func (buildErr) Error() string { return "boom" }

var errBuild = buildErr{}
