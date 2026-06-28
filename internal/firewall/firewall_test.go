package firewall

import (
	"strings"
	"testing"
	"time"
)

// withRunner swaps the package runner for the duration of a test, recording
// every command line it receives. failCheck makes idempotency checks (-C)
// report "not present" so Setup proceeds to insert rules.
func withRunner(t *testing.T) *[]string {
	t.Helper()
	var calls []string
	orig := runner
	t.Cleanup(func() { runner = orig })
	runner = func(name string, args ...string) (string, error) {
		line := name + " " + strings.Join(args, " ")
		calls = append(calls, line)
		// iptables/ip6tables -C is the "does this rule exist?" probe. Return
		// non-nil so Setup believes the rule is absent and inserts it.
		if (name == "iptables" || name == "ip6tables") && len(args) > 0 && args[0] == "-C" {
			return "", errNotFound{}
		}
		return "", nil
	}
	return &calls
}

type errNotFound struct{}

func (errNotFound) Error() string { return "not found" }

// withBinaries forces hasBinary to report the named tools as present, so the
// IPv6 setup paths run regardless of what's installed on the test host.
func withBinaries(t *testing.T, names ...string) {
	t.Helper()
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	orig := hasBinary
	t.Cleanup(func() { hasBinary = orig })
	hasBinary = func(name string) bool { return have[name] }
}

func TestIPTablesSetupInsertsPerChain(t *testing.T) {
	calls := withRunner(t)
	fw := newIPTables(Config{SetName: "bl", Chains: []string{"INPUT", "DOCKER-USER"}})
	if err := fw.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	joined := strings.Join(*calls, "\n")
	want := []string{
		"ipset create -exist bl hash:ip timeout 0",
		"iptables -I INPUT 1 -m set --match-set bl src -j DROP",
		"iptables -I DOCKER-USER 1 -m set --match-set bl src -j DROP",
	}
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Errorf("missing command %q in:\n%s", w, joined)
		}
	}
}

func TestIPTablesBanUsesSeconds(t *testing.T) {
	calls := withRunner(t)
	fw := newIPTables(Config{SetName: "bl", Chains: []string{"INPUT"}})
	if err := fw.Ban("1.2.3.4", 10*time.Minute); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	want := "ipset add -exist bl 1.2.3.4 timeout 600"
	if (*calls)[0] != want {
		t.Errorf("Ban call = %q, want %q", (*calls)[0], want)
	}
}

func TestIPTablesBanPermanent(t *testing.T) {
	calls := withRunner(t)
	fw := newIPTables(Config{SetName: "bl", Chains: []string{"INPUT"}})
	if err := fw.Ban("1.2.3.4", 0); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	want := "ipset add -exist bl 1.2.3.4 timeout 0"
	if (*calls)[0] != want {
		t.Errorf("Ban call = %q, want %q", (*calls)[0], want)
	}
}

func TestIPTablesUnban(t *testing.T) {
	calls := withRunner(t)
	fw := newIPTables(Config{SetName: "bl", Chains: []string{"INPUT"}})
	if err := fw.Unban("1.2.3.4"); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	want := "ipset del -exist bl 1.2.3.4"
	if (*calls)[0] != want {
		t.Errorf("Unban call = %q, want %q", (*calls)[0], want)
	}
}

func TestNFTablesBanPermanentOmitsTimeout(t *testing.T) {
	calls := withRunner(t)
	fw := newNFTables(Config{SetName: "bl"})
	if err := fw.Ban("5.6.7.8", 0); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	joined := strings.Join(*calls, "\n")
	if !strings.Contains(joined, "add element inet simple_blocker bl { 5.6.7.8 }") {
		t.Errorf("expected add element without timeout, got:\n%s", joined)
	}
	if strings.Contains(joined, "timeout") {
		t.Errorf("permanent ban must not include a timeout, got:\n%s", joined)
	}
}

func TestNFTablesUnban(t *testing.T) {
	calls := withRunner(t)
	fw := newNFTables(Config{SetName: "bl"})
	if err := fw.Unban("5.6.7.8"); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	joined := strings.Join(*calls, "\n")
	if !strings.Contains(joined, "delete element inet simple_blocker bl { 5.6.7.8 }") {
		t.Errorf("expected delete element, got:\n%s", joined)
	}
}

func TestNFTablesBanRefreshesElement(t *testing.T) {
	calls := withRunner(t)
	fw := newNFTables(Config{SetName: "bl"})
	if err := fw.Ban("5.6.7.8", time.Hour); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	joined := strings.Join(*calls, "\n")
	// It deletes any stale element first, then adds with a seconds timeout.
	if !strings.Contains(joined, "delete element inet simple_blocker bl { 5.6.7.8 }") {
		t.Errorf("expected delete element, got:\n%s", joined)
	}
	if !strings.Contains(joined, "add element inet simple_blocker bl { 5.6.7.8 timeout 3600s }") {
		t.Errorf("expected add element with timeout, got:\n%s", joined)
	}
}

func TestIPTablesSetupIPv6(t *testing.T) {
	calls := withRunner(t)
	withBinaries(t, "ip6tables")
	fw := newIPTables(Config{SetName: "bl", Chains: []string{"INPUT"}, EnforceIPv6: true})
	if err := fw.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	joined := strings.Join(*calls, "\n")
	for _, w := range []string{
		"ipset create -exist bl6 hash:ip family inet6 timeout 0",
		"ip6tables -I INPUT 1 -m set --match-set bl6 src -j DROP",
	} {
		if !strings.Contains(joined, w) {
			t.Errorf("missing v6 command %q in:\n%s", w, joined)
		}
	}
}

func TestIPTablesSetupNoIPv6WhenDisabled(t *testing.T) {
	calls := withRunner(t)
	fw := newIPTables(Config{SetName: "bl", Chains: []string{"INPUT"}})
	if err := fw.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	joined := strings.Join(*calls, "\n")
	if strings.Contains(joined, "inet6") || strings.Contains(joined, "ip6tables") {
		t.Errorf("v6 commands issued with enforce_ipv6 off:\n%s", joined)
	}
}

func TestIPTablesBanRoutesByFamily(t *testing.T) {
	calls := withRunner(t)
	withBinaries(t, "ip6tables")
	fw := newIPTables(Config{SetName: "bl", Chains: []string{"INPUT"}, EnforceIPv6: true})
	if err := fw.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	*calls = nil // drop Setup calls
	if err := fw.Ban("2001:db8::1", 10*time.Minute); err != nil {
		t.Fatalf("Ban v6: %v", err)
	}
	if got, want := (*calls)[0], "ipset add -exist bl6 2001:db8::1 timeout 600"; got != want {
		t.Errorf("v6 Ban = %q, want %q", got, want)
	}
	*calls = nil
	if err := fw.Ban("1.2.3.4", 0); err != nil {
		t.Fatalf("Ban v4: %v", err)
	}
	if got, want := (*calls)[0], "ipset add -exist bl 1.2.3.4 timeout 0"; got != want {
		t.Errorf("v4 Ban = %q, want %q", got, want)
	}
}

func TestIPTablesBanIPv6NoopWhenDisabled(t *testing.T) {
	calls := withRunner(t)
	fw := newIPTables(Config{SetName: "bl", Chains: []string{"INPUT"}}) // v6 off
	if err := fw.Ban("2001:db8::1", time.Minute); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if len(*calls) != 0 {
		t.Errorf("expected no command for v6 ban with enforcement off, got: %v", *calls)
	}
}

func TestIPTablesSetupIPv6ToleratesMissingIP6Tables(t *testing.T) {
	calls := withRunner(t)
	withBinaries(t) // ip6tables absent
	fw := newIPTables(Config{SetName: "bl", Chains: []string{"INPUT"}, EnforceIPv6: true})
	if err := fw.Setup(); err != nil {
		t.Fatalf("Setup must not fail when ip6tables is absent: %v", err)
	}
	joined := strings.Join(*calls, "\n")
	// v4 must still be installed; no v6 set/rule attempted.
	if !strings.Contains(joined, "iptables -I INPUT 1 -m set --match-set bl src -j DROP") {
		t.Errorf("v4 rule missing:\n%s", joined)
	}
	if strings.Contains(joined, "inet6") || strings.Contains(joined, "ip6tables") {
		t.Errorf("v6 commands attempted without ip6tables:\n%s", joined)
	}
	// A subsequent v6 ban is a silent no-op, not an error.
	*calls = nil
	if err := fw.Ban("2001:db8::1", time.Minute); err != nil {
		t.Fatalf("v6 Ban after skipped setup: %v", err)
	}
	if len(*calls) != 0 {
		t.Errorf("expected no command for v6 ban after skipped setup, got: %v", *calls)
	}
}

func TestNFTablesSetupIPv6(t *testing.T) {
	calls := withRunner(t)
	fw := newNFTables(Config{SetName: "bl", EnforceIPv6: true})
	if err := fw.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	joined := strings.Join(*calls, "\n")
	for _, w := range []string{
		"add set inet simple_blocker bl6 { type ipv6_addr ; flags timeout ; }",
		"add rule inet simple_blocker input ip6 saddr @bl6 drop",
	} {
		if !strings.Contains(joined, w) {
			t.Errorf("missing v6 command %q in:\n%s", w, joined)
		}
	}
}

func TestNFTablesBanRoutesByFamily(t *testing.T) {
	calls := withRunner(t)
	fw := newNFTables(Config{SetName: "bl", EnforceIPv6: true})
	if err := fw.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	*calls = nil
	if err := fw.Ban("2001:db8::1", time.Hour); err != nil {
		t.Fatalf("Ban v6: %v", err)
	}
	joined := strings.Join(*calls, "\n")
	if !strings.Contains(joined, "add element inet simple_blocker bl6 { 2001:db8::1 timeout 3600s }") {
		t.Errorf("expected v6 add into bl6, got:\n%s", joined)
	}
}

func TestNewUnknownBackend(t *testing.T) {
	if _, err := New("external", "pf", Config{}); err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestNewUnknownMode(t *testing.T) {
	if _, err := New("sideways", "auto", Config{}); err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestNewExternalSelectsBackend(t *testing.T) {
	fw, err := New("external", "nftables", Config{SetName: "bl"})
	if err != nil {
		t.Fatalf("New external/nftables: %v", err)
	}
	if fw.Name() != "nftables" {
		t.Errorf("Name = %q, want nftables", fw.Name())
	}
	fw, err = New("external", "iptables", Config{SetName: "bl", Chains: []string{"INPUT"}})
	if err != nil {
		t.Fatalf("New external/iptables: %v", err)
	}
	if fw.Name() != "iptables" {
		t.Errorf("Name = %q, want iptables", fw.Name())
	}
}
