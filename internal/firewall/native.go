//go:build linux

package firewall

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// native enforces bans with nftables directly over netlink — no external
// binaries. It is the "internal" firewall implementation and mirrors the exec
// nft backend exactly: an inet table holding a timeout set, with a single
// `ip saddr @set drop` rule in an input-hook chain. Teardown removes the rule
// but keeps the set, so existing bans survive a restart.
type native struct {
	setName string

	mu    sync.Mutex
	conn  *nftables.Conn
	table *nftables.Table
	set   *nftables.Set
	chain *nftables.Chain
}

func newNative(cfg Config) (Firewall, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nftables: open netlink: %w", err)
	}
	return &native{setName: cfg.SetName, conn: conn}, nil
}

func (f *native) Name() string { return "nftables-native" }

func (f *native) Setup() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// AddTable/AddSet/AddChain use create-without-exclusive semantics, so they
	// are no-ops when the objects already exist and never wipe the set's
	// elements — bans persist across restarts.
	f.table = f.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   nftTable,
	})
	f.set = &nftables.Set{
		Table:      f.table,
		Name:       f.setName,
		KeyType:    nftables.TypeIPAddr,
		HasTimeout: true, // allow per-element timeouts
	}
	if err := f.conn.AddSet(f.set, nil); err != nil {
		return fmt.Errorf("nftables: add set: %w", err)
	}
	f.chain = f.conn.AddChain(&nftables.Chain{
		Name:     nftChain,
		Table:    f.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})
	// Flush our chain then re-add the single drop rule, so re-running Setup is
	// idempotent (no duplicate rules) — same approach as the exec backend.
	f.conn.FlushChain(f.chain)
	f.conn.AddRule(&nftables.Rule{
		Table: f.table,
		Chain: f.chain,
		Exprs: f.dropExprs(),
	})
	if err := f.conn.Flush(); err != nil {
		return fmt.Errorf("nftables: setup flush: %w", err)
	}
	slog.Info("nftables-native rules installed", "table", nftTable, "set", f.setName)
	return nil
}

// dropExprs encodes `ip saddr @set drop` for an inet table. The nfproto guard
// ensures only IPv4 packets have their source address (network header offset
// 12, length 4) looked up in the set; IPv6 packets fall through.
func (f *native) dropExprs() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV4}},
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			DestRegister:  1,
			Base:          expr.PayloadBaseNetworkHeader,
			Offset:        12,
			Len:           4,
		},
		// A named set is identified by name within the table; SetID is for
		// anonymous sets and is omitted here to avoid any ID mismatch on a set
		// that already exists from a prior run.
		&expr.Lookup{SourceRegister: 1, SetName: f.set.Name},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

func (f *native) Ban(ip string, d time.Duration) error {
	addr := net.ParseIP(ip)
	if addr == nil || addr.To4() == nil {
		return fmt.Errorf("nftables: not an IPv4 address: %q", ip)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.set == nil {
		return fmt.Errorf("nftables: Ban called before Setup")
	}
	// Re-adding an existing element refreshes its timeout.
	if err := f.conn.SetAddElements(f.set, []nftables.SetElement{
		{Key: addr.To4(), Timeout: d},
	}); err != nil {
		return fmt.Errorf("nftables: add element: %w", err)
	}
	return f.conn.Flush()
}

// List reads the set's elements over netlink. It works without a prior Setup
// by resolving the set by name, so a standalone "status" can read live bans.
func (f *native) List(ctx context.Context) ([]BanEntry, error) {
	// The google/nftables netlink calls below are synchronous and cannot be
	// cancelled mid-flight, so honoring ctx is best-effort: we bail before
	// starting if it is already done. In practice these local netlink reads
	// return promptly.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	set := f.set
	if set == nil {
		s, err := f.conn.GetSetByName(
			&nftables.Table{Family: nftables.TableFamilyINet, Name: nftTable},
			f.setName,
		)
		if err != nil {
			return nil, fmt.Errorf("nftables: get set %q: %w", f.setName, err)
		}
		set = s
	}
	els, err := f.conn.GetSetElements(set)
	if err != nil {
		return nil, fmt.Errorf("nftables: get set elements: %w", err)
	}
	entries := make([]BanEntry, 0, len(els))
	for _, el := range els {
		entries = append(entries, BanEntry{
			IP:      net.IP(el.Key).String(),
			Expires: el.Expires,
		})
	}
	return entries, nil
}

func (f *native) Teardown() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.chain == nil {
		return nil
	}
	// Remove the drop rule but keep the set so existing bans persist.
	f.conn.FlushChain(f.chain)
	if err := f.conn.Flush(); err != nil {
		return fmt.Errorf("nftables: teardown flush: %w", err)
	}
	slog.Info("nftables-native drop rule removed", "table", nftTable)
	return nil
}
