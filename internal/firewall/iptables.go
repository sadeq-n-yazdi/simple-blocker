package firewall

import (
	"bufio"
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// ipTables enforces bans with an ipset hash:ip set referenced from one or
// more iptables chains. This mirrors the original Python prototype. When IPv6
// enforcement is enabled it maintains a parallel `hash:ip family inet6` set
// referenced from ip6tables.
type ipTables struct {
	set    string
	set6   string
	chains []string
	v6     bool // EnforceIPv6 requested
	v6Live bool // v6 set actually created during Setup (ip6tables present)
}

func newIPTables(cfg Config) *ipTables {
	chains := cfg.Chains
	if len(chains) == 0 {
		chains = []string{"INPUT"}
	}
	return &ipTables{
		set:    cfg.SetName,
		set6:   v6SetName(cfg.SetName),
		chains: chains,
		v6:     cfg.EnforceIPv6,
	}
}

func (f *ipTables) Name() string { return "iptables" }

func (f *ipTables) Setup() error {
	// Create the ipset (idempotent via -exist). timeout 0 = entries may set
	// their own timeout; the set itself never expires.
	if err := run("ipset", "create", "-exist", f.set, "hash:ip", "timeout", "0"); err != nil {
		return err
	}
	for _, chain := range f.chains {
		if f.ruleExists(chain) {
			slog.Info("iptables rule already present", "chain", chain)
			continue
		}
		if err := run("iptables", append([]string{"-I", chain, "1"}, f.matchArgs()...)...); err != nil {
			return err
		}
		slog.Info("iptables rule added", "chain", chain)
	}
	if f.v6 {
		f.setupV6()
	}
	return nil
}

// setupV6 creates the IPv6 ban set and inserts the ip6tables drop rules. It is
// best-effort: a missing ip6tables binary or a chain that does not exist for
// IPv6 (common on Docker hosts without IPv6) is logged and skipped, never
// fatal, so a working IPv4 daemon is not taken down by enabling enforce_ipv6.
func (f *ipTables) setupV6() {
	if !hasBinary("ip6tables") {
		slog.Warn("enforce_ipv6 set but ip6tables not found; IPv6 enforcement disabled")
		return
	}
	if err := run("ipset", "create", "-exist", f.set6, "hash:ip", "family", "inet6", "timeout", "0"); err != nil {
		slog.Warn("ipv6 ipset create failed; IPv6 enforcement disabled", "err", err)
		return
	}
	f.v6Live = true
	for _, chain := range f.chains {
		if f.rule6Exists(chain) {
			slog.Info("ip6tables rule already present", "chain", chain)
			continue
		}
		if err := run("ip6tables", append([]string{"-I", chain, "1"}, f.matchArgs6()...)...); err != nil {
			slog.Warn("ip6tables rule insert failed; skipping chain", "chain", chain, "err", err)
			continue
		}
		slog.Info("ip6tables rule added", "chain", chain)
	}
}

func (f *ipTables) Ban(ip string, d time.Duration) error {
	set := f.set
	if v6, ok := isIPv6(ip); ok && v6 {
		if !f.v6Live {
			// enforce_ipv6 is off or its setup was skipped; don't error per hit.
			slog.Debug("ipv6 enforcement not active, skipping ban", "ip", ip)
			return nil
		}
		set = f.set6
	}
	// timeout 0 = permanent (ipset never expires the element). Clamp d<=0 to 0
	// so a non-positive duration honors the permanent-ban convention rather than
	// emitting a negative timeout.
	secs := 0
	if d > 0 {
		secs = int(d.Seconds())
	}
	return run("ipset", "add", "-exist", set, ip, "timeout", strconv.Itoa(secs))
}

func (f *ipTables) Unban(ip string) error {
	set := f.set
	if v6, ok := isIPv6(ip); ok && v6 {
		if !f.v6 {
			return nil // v6 not in use at all
		}
		set = f.set6
	}
	// -exist suppresses the error when the element is not in the set.
	return run("ipset", "del", "-exist", set, ip)
}

// List parses `ipset list <set>`. Members appear after a "Members:" line, one
// per line as "<ip>" optionally followed by "timeout <remaining-seconds>".
func (f *ipTables) List(ctx context.Context) ([]BanEntry, error) {
	out, err := listRunner(ctx, "ipset", "list", f.set)
	if err != nil {
		return nil, err
	}
	entries := parseIPSetList(out)
	if f.v6 {
		// Best-effort: the v6 set may not exist yet (e.g. a standalone `status`
		// before the daemon ever set it up), so a read error just means "no v6
		// bans to report" rather than a hard failure.
		if out6, err := listRunner(ctx, "ipset", "list", f.set6); err == nil {
			entries = append(entries, parseIPSetList(out6)...)
		}
	}
	return entries, nil
}

func parseIPSetList(out string) []BanEntry {
	var entries []BanEntry
	sc := bufio.NewScanner(strings.NewReader(out))
	inMembers := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !inMembers {
			if line == "Members:" {
				inMembers = true
			}
			continue
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		e := BanEntry{IP: fields[0]}
		for i := 1; i+1 < len(fields); i++ {
			if fields[i] == "timeout" {
				if secs, err := strconv.Atoi(fields[i+1]); err == nil {
					e.Expires = time.Duration(secs) * time.Second
				}
			}
		}
		entries = append(entries, e)
	}
	return entries
}

func (f *ipTables) Teardown() error {
	for _, chain := range f.chains {
		if !f.ruleExists(chain) {
			slog.Info("iptables rule already absent", "chain", chain)
			continue
		}
		if err := run("iptables", append([]string{"-D", chain}, f.matchArgs()...)...); err != nil {
			return err
		}
		slog.Info("iptables rule deleted", "chain", chain)
	}
	if f.v6 && hasBinary("ip6tables") {
		for _, chain := range f.chains {
			if !f.rule6Exists(chain) {
				continue
			}
			if err := run("ip6tables", append([]string{"-D", chain}, f.matchArgs6()...)...); err != nil {
				slog.Warn("ip6tables rule delete failed", "chain", chain, "err", err)
				continue
			}
			slog.Info("ip6tables rule deleted", "chain", chain)
		}
	}
	// The ipsets are deliberately kept so existing bans survive a restart.
	return nil
}

// matchArgs is the rule body shared by -C/-I/-D: drop packets whose source
// is in the banned set.
func (f *ipTables) matchArgs() []string {
	return []string{"-m", "set", "--match-set", f.set, "src", "-j", "DROP"}
}

func (f *ipTables) ruleExists(chain string) bool {
	return runOK("iptables", append([]string{"-C", chain}, f.matchArgs()...)...)
}

// matchArgs6 is the ip6tables counterpart of matchArgs, referencing the v6 set.
func (f *ipTables) matchArgs6() []string {
	return []string{"-m", "set", "--match-set", f.set6, "src", "-j", "DROP"}
}

func (f *ipTables) rule6Exists(chain string) bool {
	return runOK("ip6tables", append([]string{"-C", chain}, f.matchArgs6()...)...)
}
