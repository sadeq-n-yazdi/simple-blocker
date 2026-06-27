package firewall

import (
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
	timeout := strconv.Itoa(int(d.Seconds())) + "s"
	// `add element` errors if the element already exists, so drop any prior
	// entry first (ignoring "not found") to refresh its timeout.
	_, _ = runner("nft", "delete", "element", "inet", nftTable, f.set, "{", ip, "}")
	return run("nft", "add", "element", "inet", nftTable, f.set,
		"{", ip, "timeout", timeout, "}")
}

func (f *nfTables) Teardown() error {
	// Drop the enforcing rule but keep the table/set so existing bans persist.
	if err := run("nft", "flush", "chain", "inet", nftTable, nftChain); err != nil {
		return err
	}
	slog.Info("nftables drop rule removed", "table", nftTable)
	return nil
}
