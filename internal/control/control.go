// Package control exposes the daemon's live state over a read-only unix socket.
//
// The daemon calls Serve to listen; the `status` command calls Dial to fetch a
// single JSON Snapshot. The socket accepts no commands — it only reports.
package control

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"
)

// DefaultSocket is where the daemon listens unless overridden.
const DefaultSocket = "/run/simple-blocker.sock"

// Ban is one currently-banned address in the firewall set.
type Ban struct {
	IP             string `json:"ip"`
	ExpiresSeconds int64  `json:"expires_seconds"`
}

// Offender is one address the offense tracker is currently counting.
type Offender struct {
	IP              string `json:"ip"`
	Count           int    `json:"count"`
	WouldBanSeconds int64  `json:"would_ban_seconds"`
}

// Snapshot is the daemon's state at a point in time.
type Snapshot struct {
	Backend   string     `json:"backend"`
	Bans      []Ban      `json:"bans"`
	Offenders []Offender `json:"offenders"`
	TS        string     `json:"ts"`
	// Error is set when the daemon could not build the snapshot (e.g. the
	// firewall list failed); Bans/Offenders are then empty.
	Error string `json:"error,omitempty"`
}

// Serve listens on a unix socket at path and answers each connection with one
// JSON Snapshot built by build, then closes it. It returns when ctx is
// cancelled. The socket file is created 0600 and removed on shutdown.
func Serve(ctx context.Context, path string, build func() (Snapshot, error)) error {
	_ = os.Remove(path) // clear a stale socket from a hard crash
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("control: listen %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		slog.Warn("control: chmod socket", "err", err)
	}
	slog.Info("control socket listening", "path", path)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
		_ = os.Remove(path)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // expected: we closed the listener
			}
			return fmt.Errorf("control: accept: %w", err)
		}
		go serveConn(conn, build)
	}
}

func serveConn(conn net.Conn, build func() (Snapshot, error)) {
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	snap, err := build()
	if err != nil {
		snap = Snapshot{Error: err.Error(), TS: time.Now().UTC().Format(time.RFC3339)}
	}
	_ = json.NewEncoder(conn).Encode(snap)
}

// Dial connects to the daemon's control socket and reads one Snapshot.
func Dial(path string) (Snapshot, error) {
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return Snapshot{}, err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var snap Snapshot
	if err := json.NewDecoder(conn).Decode(&snap); err != nil {
		return Snapshot{}, fmt.Errorf("control: decode snapshot: %w", err)
	}
	return snap, nil
}
