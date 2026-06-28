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
// more iptables chains. This mirrors the original Python prototype.
type ipTables struct {
	set    string
	chains []string
}

func newIPTables(cfg Config) *ipTables {
	chains := cfg.Chains
	if len(chains) == 0 {
		chains = []string{"INPUT"}
	}
	return &ipTables{set: cfg.SetName, chains: chains}
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
	return nil
}

func (f *ipTables) Ban(ip string, d time.Duration) error {
	// timeout 0 = permanent (ipset never expires the element). Clamp d<=0 to 0
	// so a non-positive duration honors the permanent-ban convention rather than
	// emitting a negative timeout.
	secs := 0
	if d > 0 {
		secs = int(d.Seconds())
	}
	return run("ipset", "add", "-exist", f.set, ip, "timeout", strconv.Itoa(secs))
}

func (f *ipTables) Unban(ip string) error {
	// -exist suppresses the error when the element is not in the set.
	return run("ipset", "del", "-exist", f.set, ip)
}

// List parses `ipset list <set>`. Members appear after a "Members:" line, one
// per line as "<ip>" optionally followed by "timeout <remaining-seconds>".
func (f *ipTables) List(ctx context.Context) ([]BanEntry, error) {
	out, err := listRunner(ctx, "ipset", "list", f.set)
	if err != nil {
		return nil, err
	}
	return parseIPSetList(out), nil
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
	// The ipset is deliberately kept so existing bans survive a restart.
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
