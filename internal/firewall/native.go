//go:build linux

package firewall

import (
	"context"
	"errors"
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
	setName  string
	set6Name string
	v6       bool // EnforceIPv6 requested

	mu     sync.Mutex
	conn   *nftables.Conn
	table  *nftables.Table
	set    *nftables.Set
	set6   *nftables.Set
	chain  *nftables.Chain
	v6Live bool // v6 set + rule actually installed during Setup
}

func newNative(cfg Config) (Firewall, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("nftables: open netlink: %w", err)
	}
	return &native{
		setName:  cfg.SetName,
		set6Name: v6SetName(cfg.SetName),
		v6:       cfg.EnforceIPv6,
		conn:     conn,
	}, nil
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

	if f.v6 {
		// Best-effort: a v6 failure disables v6 enforcement but must not take
		// down the working IPv4 path, so it is applied in its own flush.
		if err := f.setupV6(); err != nil {
			slog.Warn("nftables-native: IPv6 enforcement disabled", "err", err)
			f.v6Live = false
		} else {
			f.v6Live = true
			slog.Info("nftables-native IPv6 rules installed", "table", nftTable, "set", f.set6Name)
		}
	}
	return nil
}

// setupV6 adds the IPv6 set and appends the `ip6 saddr @set6 drop` rule to the
// (already-flushed) chain, in a separate flush so a v6 failure cannot roll back
// the v4 rule. Re-running Setup re-flushes the chain and re-applies both rules.
func (f *native) setupV6() error {
	f.set6 = &nftables.Set{
		Table:      f.table,
		Name:       f.set6Name,
		KeyType:    nftables.TypeIP6Addr,
		HasTimeout: true,
	}
	if err := f.conn.AddSet(f.set6, nil); err != nil {
		f.set6 = nil
		return fmt.Errorf("add IPv6 set: %w", err)
	}
	f.conn.AddRule(&nftables.Rule{
		Table: f.table,
		Chain: f.chain,
		Exprs: f.dropExprs6(),
	})
	if err := f.conn.Flush(); err != nil {
		f.set6 = nil
		return fmt.Errorf("flush: %w", err)
	}
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

// dropExprs6 encodes `ip6 saddr @set6 drop` for the inet table. The nfproto
// guard restricts the lookup to IPv6 packets, whose source address sits at
// network-header offset 8, length 16.
func (f *native) dropExprs6() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.NFPROTO_IPV6}},
		&expr.Payload{
			OperationType: expr.PayloadLoad,
			DestRegister:  1,
			Base:          expr.PayloadBaseNetworkHeader,
			Offset:        8,
			Len:           16,
		},
		&expr.Lookup{SourceRegister: 1, SetName: f.set6.Name},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
}

func (f *native) Ban(ip string, d time.Duration) error {
	addr := net.ParseIP(ip)
	if addr == nil {
		return fmt.Errorf("nftables: invalid IP: %q", ip)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if v4 := addr.To4(); v4 != nil {
		if f.set == nil {
			return fmt.Errorf("nftables: Ban called before Setup")
		}
		// Re-adding an existing element refreshes its timeout.
		if err := f.conn.SetAddElements(f.set, []nftables.SetElement{
			{Key: v4, Timeout: d},
		}); err != nil {
			return fmt.Errorf("nftables: add element: %w", err)
		}
		return f.conn.Flush()
	}
	// IPv6.
	if !f.v6Live || f.set6 == nil {
		slog.Debug("nftables-native: ipv6 enforcement not active, skipping ban", "ip", ip)
		return nil
	}
	if err := f.conn.SetAddElements(f.set6, []nftables.SetElement{
		{Key: addr.To16(), Timeout: d},
	}); err != nil {
		return fmt.Errorf("nftables: add IPv6 element: %w", err)
	}
	return f.conn.Flush()
}

func (f *native) Unban(ip string) error {
	addr := net.ParseIP(ip)
	if addr == nil {
		return fmt.Errorf("nftables: invalid IP: %q", ip)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if v4 := addr.To4(); v4 != nil {
		set, err := f.resolveSet()
		if err != nil {
			return err
		}
		return f.deleteElement(set, v4)
	}
	// IPv6: nothing to do if v6 was never configured.
	if !f.v6 {
		return nil
	}
	set6, err := f.resolveSet6()
	if err != nil {
		return err
	}
	return f.deleteElement(set6, addr.To16())
}

// resolveSet returns the cached v4 set, resolving it by name on first use so
// Unban/List work without a prior Setup (e.g. a standalone CLI invocation).
func (f *native) resolveSet() (*nftables.Set, error) {
	if f.set != nil {
		return f.set, nil
	}
	s, err := f.conn.GetSetByName(
		&nftables.Table{Family: nftables.TableFamilyINet, Name: nftTable},
		f.setName,
	)
	if err != nil {
		return nil, fmt.Errorf("nftables: get set %q: %w", f.setName, err)
	}
	f.set = s // cache so a liftLiveBans loop doesn't re-query per call
	return s, nil
}

func (f *native) resolveSet6() (*nftables.Set, error) {
	if f.set6 != nil {
		return f.set6, nil
	}
	s, err := f.conn.GetSetByName(
		&nftables.Table{Family: nftables.TableFamilyINet, Name: nftTable},
		f.set6Name,
	)
	if err != nil {
		return nil, fmt.Errorf("nftables: get set %q: %w", f.set6Name, err)
	}
	f.set6 = s
	return s, nil
}

// deleteElement removes key from set, treating an absent element (ENOENT) as a
// no-op to satisfy the Unban contract, matching the other backends.
func (f *native) deleteElement(set *nftables.Set, key []byte) error {
	if err := f.conn.SetDeleteElements(set, []nftables.SetElement{{Key: key}}); err != nil {
		return fmt.Errorf("nftables: delete element: %w", err)
	}
	if err := f.conn.Flush(); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("nftables: flush: %w", err)
	}
	return nil
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
	set, err := f.resolveSet()
	if err != nil {
		return nil, err
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
	if f.v6 {
		// Best-effort: a missing v6 set just means no v6 bans to report.
		if set6, err := f.resolveSet6(); err == nil {
			if els6, err := f.conn.GetSetElements(set6); err == nil {
				for _, el := range els6 {
					entries = append(entries, BanEntry{
						IP:      net.IP(el.Key).String(),
						Expires: el.Expires,
					})
				}
			}
		}
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
