package control

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestServeCleansUpOnCancel(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "ctl.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, sock, func() (Snapshot, error) { return Snapshot{}, nil }) }()

	// Wait for the socket to appear.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned error on cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("socket file not removed after shutdown: %v", err)
	}
}

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
