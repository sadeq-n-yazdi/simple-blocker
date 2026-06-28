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
// ipset/iptables are unavailable.
type nfTables struct {
	set string
}

func newNFTables(cfg Config) *nfTables {
	return &nfTables{set: cfg.SetName}
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
	slog.Info("nftables rules installed", "table", nftTable, "set", f.set)
	return nil
}

func (f *nfTables) Ban(ip string, d time.Duration) error {
	// `add element` errors if the element already exists, so drop any prior
	// entry first (ignoring "not found") to refresh its timeout.
	_, _ = runner("nft", "delete", "element", "inet", nftTable, f.set, "{", ip, "}")
	// A duration <= 0 is a permanent ban: omit the timeout tokens entirely, as
	// `timeout 0s` is rejected by nft.
	if d <= 0 {
		return run("nft", "add", "element", "inet", nftTable, f.set, "{", ip, "}")
	}
	timeout := strconv.Itoa(int(d.Seconds())) + "s"
	return run("nft", "add", "element", "inet", nftTable, f.set,
		"{", ip, "timeout", timeout, "}")
}

func (f *nfTables) Unban(ip string) error {
	// Ignore "not found" so removing an absent element is a no-op.
	_, _ = runner("nft", "delete", "element", "inet", nftTable, f.set, "{", ip, "}")
	return nil
}

// List runs `nft -j list set …` and parses the JSON elements. Each element is
// either a bare address string or an object carrying timeout/expires (seconds).
func (f *nfTables) List(ctx context.Context) ([]BanEntry, error) {
	out, err := listRunner(ctx, "nft", "-j", "list", "set", "inet", nftTable, f.set)
	if err != nil {
		return nil, err
	}
	return parseNFTSetJSON(out)
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
