package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"time"
)

// nfTable name that holds our set and chain. Kept separate from other
// rulesets so we can flush it without touching anything else.
const nftTable = "simple_blocker"

// nftChain is our dedicated input-hook chain.
const nftChain = "input"

// nfTables enforces bans with a native nftables set (flags timeout) and a
// drop rule in a dedicated inet table. It is the portable fallback used when
// ipset/iptables are unavailable. When IPv6 enforcement is enabled it adds a
// parallel ipv6_addr set and an `ip6 saddr @set6 drop` rule in the same inet
// table.
type nfTables struct {
	set    string
	set6   string
	v6     bool // EnforceIPv6 requested
	v6Live bool // v6 set actually created during Setup
}

func newNFTables(cfg Config) *nfTables {
	return &nfTables{
		set:  cfg.SetName,
		set6: v6SetName(cfg.SetName),
		v6:   cfg.EnforceIPv6,
	}
}

func (f *nfTables) Name() string { return "nftables" }

func (f *nfTables) Setup() error {
	// `nft add table/set/chain` are idempotent (no error if they exist).
	if err := run("nft", "add", "table", "inet", nftTable); err != nil {
		return err
	}
	if err := run("nft", "add", "set", "inet", nftTable, f.set,
		"{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}"); err != nil {
		return err
	}
	if f.v6 {
		// The inet table holds both families, so the v6 set lives alongside the
		// v4 one. A failure here disables v6 but must not take down v4.
		if err := run("nft", "add", "set", "inet", nftTable, f.set6,
			"{", "type", "ipv6_addr", ";", "flags", "timeout", ";", "}"); err != nil {
			slog.Warn("nftables IPv6 set create failed; IPv6 enforcement disabled", "err", err)
		} else {
			f.v6Live = true
		}
	}
	if err := run("nft", "add", "chain", "inet", nftTable, nftChain,
		"{", "type", "filter", "hook", "input", "priority", "0", ";", "}"); err != nil {
		return err
	}
	// Adding a rule is not idempotent, so flush our chain first and re-add the
	// single drop rule. Safe because the chain is exclusively ours.
	if err := run("nft", "flush", "chain", "inet", nftTable, nftChain); err != nil {
		return err
	}
	if err := run("nft", "add", "rule", "inet", nftTable, nftChain,
		"ip", "saddr", "@"+f.set, "drop"); err != nil {
		return err
	}
	if f.v6Live {
		// Appended after the v4 rule in the same (freshly flushed) chain.
		if err := run("nft", "add", "rule", "inet", nftTable, nftChain,
			"ip6", "saddr", "@"+f.set6, "drop"); err != nil {
			slog.Warn("nftables IPv6 rule add failed; IPv6 enforcement disabled", "err", err)
			f.v6Live = false
		} else {
			slog.Info("nftables IPv6 rule installed", "table", nftTable, "set", f.set6)
		}
	}
	slog.Info("nftables rules installed", "table", nftTable, "set", f.set)
	return nil
}

// setFor selects the v4 or v6 set name for ip. The second return is false when
// ip is a v6 address but v6 enforcement is not in use, signalling the caller to
// no-op rather than touch a set that may not exist.
func (f *nfTables) setFor(ip string, requireLive bool) (string, bool) {
	if v6, ok := isIPv6(ip); ok && v6 {
		if (requireLive && !f.v6Live) || (!requireLive && !f.v6) {
			return "", false
		}
		return f.set6, true
	}
	return f.set, true
}

func (f *nfTables) Ban(ip string, d time.Duration) error {
	set, ok := f.setFor(ip, true)
	if !ok {
		slog.Debug("ipv6 enforcement not active, skipping ban", "ip", ip)
		return nil
	}
	// `add element` errors if the element already exists, so drop any prior
	// entry first (ignoring "not found") to refresh its timeout.
	_, _ = runner("nft", "delete", "element", "inet", nftTable, set, "{", ip, "}")
	// A duration <= 0 is a permanent ban: omit the timeout tokens entirely, as
	// `timeout 0s` is rejected by nft.
	if d <= 0 {
		return run("nft", "add", "element", "inet", nftTable, set, "{", ip, "}")
	}
	timeout := strconv.Itoa(int(d.Seconds())) + "s"
	return run("nft", "add", "element", "inet", nftTable, set,
		"{", ip, "timeout", timeout, "}")
}

func (f *nfTables) Unban(ip string) error {
	set, ok := f.setFor(ip, false)
	if !ok {
		return nil // v6 not in use
	}
	// Ignore "not found" so removing an absent element is a no-op.
	_, _ = runner("nft", "delete", "element", "inet", nftTable, set, "{", ip, "}")
	return nil
}

// List runs `nft -j list set …` and parses the JSON elements. Each element is
// either a bare address string or an object carrying timeout/expires (seconds).
func (f *nfTables) List(ctx context.Context) ([]BanEntry, error) {
	out, err := listRunner(ctx, "nft", "-j", "list", "set", "inet", nftTable, f.set)
	if err != nil {
		return nil, err
	}
	entries, err := parseNFTSetJSON(out)
	if err != nil {
		return nil, err
	}
	if f.v6 {
		// Best-effort: the v6 set may not exist (e.g. standalone status before
		// the daemon set it up), so a read error means "no v6 bans" not failure.
		if out6, err := listRunner(ctx, "nft", "-j", "list", "set", "inet", nftTable, f.set6); err == nil {
			v6entries, err := parseNFTSetJSON(out6)
			if err != nil {
				return nil, err
			}
			entries = append(entries, v6entries...)
		}
	}
	return entries, nil
}

func parseNFTSetJSON(out string) ([]BanEntry, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil, fmt.Errorf("nft list: parse json: %w", err)
	}
	var entries []BanEntry
	for _, obj := range doc.Nftables {
		raw, ok := obj["set"]
		if !ok {
			continue
		}
		var set struct {
			Elem []json.RawMessage `json:"elem"`
		}
		if err := json.Unmarshal(raw, &set); err != nil {
			return nil, fmt.Errorf("nft list: parse set: %w", err)
		}
		for _, el := range set.Elem {
			// Bare string element (no timeout attributes).
			var ip string
			if err := json.Unmarshal(el, &ip); err == nil {
				entries = append(entries, BanEntry{IP: ip})
				continue
			}
			// Object element: {"elem":{"val":"1.2.3.4","expires":59}}.
			var wrap struct {
				Elem struct {
					Val     string `json:"val"`
					Expires int    `json:"expires"`
				} `json:"elem"`
			}
			if err := json.Unmarshal(el, &wrap); err == nil && wrap.Elem.Val != "" {
				entries = append(entries, BanEntry{
					IP:      wrap.Elem.Val,
					Expires: time.Duration(wrap.Elem.Expires) * time.Second,
				})
				continue
			}
			// Neither shape matched: fail loudly rather than under-report bans
			// (a silent skip would make status show fewer IPs than exist).
			return nil, fmt.Errorf("nft list: unexpected element format: %s", string(el))
		}
	}
	return entries, nil
}

func (f *nfTables) Teardown() error {
	// Drop the enforcing rule but keep the table/set so existing bans persist.
	if err := run("nft", "flush", "chain", "inet", nftTable, nftChain); err != nil {
		return err
	}
	slog.Info("nftables drop rule removed", "table", nftTable)
	return nil
}
