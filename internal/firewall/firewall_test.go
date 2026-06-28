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
		// iptables -C is the "does this rule exist?" probe. Return non-nil so
		// Setup believes the rule is absent and inserts it.
		if name == "iptables" && len(args) > 0 && args[0] == "-C" {
			return "", errNotFound{}
		}
		return "", nil
	}
	return &calls
}

type errNotFound struct{}

func (errNotFound) Error() string { return "not found" }

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
