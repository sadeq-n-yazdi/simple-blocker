package blocker

import (
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"code.sadeq.uk/simple-blocker/internal/ipmatch"
)

// Banner applies a ban to an IP for a duration. *firewall.Firewall satisfies
// it; the narrow interface keeps the engine testable without a real firewall.
//
// A duration d <= 0 means a permanent ban (no expiry).
type Banner interface {
	Ban(ip string, d time.Duration) error
}

// listSet is the pair of matchers swapped atomically on a config reload.
type listSet struct {
	white *ipmatch.List
	black *ipmatch.List
}

// Engine connects offense reports to ban enforcement.
type Engine struct {
	tracker   *Tracker
	banner    Banner
	lists     atomic.Pointer[listSet]
	enforceV6 bool
}

// NewEngine wires a tracker to a banner with the initial whitelist/blacklist.
// enforceV6 mirrors firewall.Config.EnforceIPv6: when false, IPv6 targets are
// skipped at the ban chokepoint so they don't reach a backend that isn't set up
// to enforce them.
func NewEngine(tracker *Tracker, banner Banner, white, black *ipmatch.List, enforceV6 bool) *Engine {
	e := &Engine{tracker: tracker, banner: banner, enforceV6: enforceV6}
	e.lists.Store(&listSet{white: white, black: black})
	return e
}

// SetLists atomically swaps the whitelist/blacklist. It is called by the
// config-reload watcher and is safe to use while sources are reporting.
func (e *Engine) SetLists(white, black *ipmatch.List) {
	e.lists.Store(&listSet{white: white, black: black})
}

// Report records an offense for ip and bans it when policy says so: a
// whitelisted IP is never banned; a blacklisted IP is banned permanently; any
// other IP follows the escalating schedule. It is safe for concurrent use and
// is the callback handed to sources.
func (e *Engine) Report(ip, src string) {
	// Normalize IPv4-mapped IPv6 (e.g. ::ffff:1.2.3.4) to plain IPv4 so the
	// tracker doesn't count it as a distinct offender and the backends receive
	// a syntax they accept.
	if addr, err := netip.ParseAddr(ip); err == nil {
		ip = addr.Unmap().String()
	}
	ls := e.lists.Load()
	if ls.white.Contains(ip) {
		slog.Debug("whitelisted, not banning", "ip", ip, "source", src)
		return
	}
	if ls.black.Contains(ip) {
		e.ban(ip, src, 0, "blacklist", 0) // 0 duration = permanent
		return
	}
	ban, count := e.tracker.Record(ip)
	if ban <= 0 {
		return
	}
	e.ban(ip, src, ban, "schedule", count)
}

// ban enforces a single ban. An unparseable address is always skipped. An IPv6
// target is skipped unless v6 enforcement is enabled (the backends only build a
// v6 set when enforce_ipv6 is on), avoiding a per-hit backend error.
func (e *Engine) ban(ip, src string, d time.Duration, reason string, count int) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		slog.Warn("unparseable address, skipping ban", "ip", ip, "source", src, "reason", reason)
		return
	}
	if addr.Is6() && !addr.Is4In6() && !e.enforceV6 {
		slog.Debug("ipv6 enforcement disabled, skipping", "ip", ip, "source", src, "reason", reason)
		return
	}
	if err := e.banner.Ban(ip, d); err != nil {
		slog.Error("ban failed", "ip", ip, "source", src, "err", err)
		return
	}
	if d <= 0 {
		slog.Info("banned", "ip", ip, "source", src, "list", reason, "duration", "permanent")
		return
	}
	slog.Info("banned", "ip", ip, "source", src, "offenses", count, "duration", d)
}
