// Package firewall enforces IP bans through a pluggable backend.
//
// The Firewall interface abstracts over concrete backends (iptables+ipset,
// nftables). New backends only need to satisfy the interface to be wired in.
package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// Firewall installs and removes the rules that drop traffic from banned IPs.
type Firewall interface {
	// Name returns the backend's identifier (e.g. "iptables").
	Name() string
	// Setup creates the backing set and installs the drop rules. It must be
	// idempotent so restarts are safe.
	Setup() error
	// Ban adds ip to the banned set for the given duration. A duration d <= 0
	// means a permanent ban (no expiry).
	Ban(ip string, d time.Duration) error
	// Unban removes ip from the banned set. It is a no-op if ip is absent.
	Unban(ip string) error
	// List returns the IPs currently in the banned set with their remaining
	// time. It must work without a prior Setup so a standalone "status" can
	// read the set directly. The context bounds the underlying firewall query
	// so a hung command can't block the caller indefinitely.
	List(ctx context.Context) ([]BanEntry, error)
	// Teardown removes the drop rules. The banned set is intentionally left
	// in place so existing bans survive a restart.
	Teardown() error
}

// BanEntry is one address in the banned set.
type BanEntry struct {
	IP string
	// Expires is the remaining time before the ban lifts. It is 0 when the
	// backend cannot report it (e.g. a permanent entry).
	Expires time.Duration
}

// Config holds the settings a backend needs to build its rules.
type Config struct {
	SetName string   // ipset / nft set name
	Chains  []string // iptables chains (ignored by nftables)
	// EnforceIPv6 requests a parallel IPv6 ban set + drop rule. It is opt-in and
	// best-effort: a backend that cannot establish IPv6 enforcement (no
	// ip6tables, a missing chain, an unsupported kernel) logs and skips it
	// rather than failing Setup, and a v6 Ban it cannot enforce is a no-op. The
	// IPv6 set name is derived from SetName (see v6SetName).
	EnforceIPv6 bool
}

// New constructs a firewall backend.
//
// mode selects the implementation: "internal" uses pure-Go nftables over
// netlink (no external binaries); "external" (or "") shells out to the host's
// firewall tools. backend only applies in external mode and is "auto",
// "iptables" or "nftables"; "auto" picks iptables+ipset when both are present,
// otherwise nftables.
func New(mode, backend string, cfg Config) (Firewall, error) {
	switch mode {
	case "internal":
		return newNative(cfg)
	case "external", "":
		return newExternal(backend, cfg)
	default:
		return nil, fmt.Errorf("unknown firewall mode %q (use internal or external)", mode)
	}
}

func newExternal(backend string, cfg Config) (Firewall, error) {
	switch backend {
	case "iptables":
		return newIPTables(cfg), nil
	case "nftables":
		return newNFTables(cfg), nil
	case "auto", "":
		return autodetect(cfg)
	default:
		return nil, fmt.Errorf("unknown firewall backend %q", backend)
	}
}

func autodetect(cfg Config) (Firewall, error) {
	if hasBinary("ipset") && hasBinary("iptables") {
		return newIPTables(cfg), nil
	}
	if hasBinary("nft") {
		return newNFTables(cfg), nil
	}
	return nil, fmt.Errorf("no supported firewall found: install ipset+iptables or nftables")
}

// hasBinary reports whether name is on PATH. It is a package variable so tests
// can simulate the presence (or absence) of tools like ip6tables.
var hasBinary = func(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
