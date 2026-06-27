package blocker

import (
	"log/slog"
	"time"
)

// Banner applies a ban to an IP for a duration. *firewall.Firewall satisfies
// it; the narrow interface keeps the engine testable without a real firewall.
type Banner interface {
	Ban(ip string, d time.Duration) error
}

// Engine connects offense reports to ban enforcement.
type Engine struct {
	tracker *Tracker
	banner  Banner
}

// NewEngine wires a tracker to a banner.
func NewEngine(tracker *Tracker, banner Banner) *Engine {
	return &Engine{tracker: tracker, banner: banner}
}

// Report records an offense for ip and bans it when the schedule says so.
// It is safe for concurrent use and is the callback handed to sources.
func (e *Engine) Report(ip, src string) {
	ban, count := e.tracker.Record(ip)
	if ban <= 0 {
		return
	}
	if err := e.banner.Ban(ip, ban); err != nil {
		slog.Error("ban failed", "ip", ip, "source", src, "err", err)
		return
	}
	slog.Info("banned", "ip", ip, "source", src, "offenses", count, "duration", ban)
}
