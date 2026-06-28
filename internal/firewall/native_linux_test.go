//go:build linux

package firewall

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestNewInternalSelectsNative(t *testing.T) {
	fw, err := New("internal", "", Config{SetName: "bl"})
	if err != nil {
		// Opening the netlink socket can be blocked in restricted sandboxes;
		// that is environmental, not a logic failure.
		t.Skipf("cannot open netlink: %v", err)
	}
	if fw.Name() != "nftables-native" {
		t.Errorf("Name = %q, want nftables-native", fw.Name())
	}
}

// TestNativeIntegration exercises the real netlink path. It needs root
// (CAP_NET_ADMIN) and a kernel with nftables, so it skips otherwise.
func TestNativeIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for netlink firewall operations")
	}
	fw, err := New("internal", "", Config{SetName: "sb_test_set", EnforceIPv6: true})
	if err != nil {
		t.Skipf("cannot open netlink: %v", err)
	}
	if err := fw.Setup(); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	// Re-running Setup must be idempotent (no duplicate rules, set intact).
	if err := fw.Setup(); err != nil {
		t.Fatalf("Setup (re-run): %v", err)
	}
	if err := fw.Ban("203.0.113.7", time.Minute); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	// A v6 ban exercises the parallel ipv6_addr set + drop rule.
	if err := fw.Ban("2001:db8::dead", time.Minute); err != nil {
		t.Fatalf("Ban v6: %v", err)
	}
	// List must see both banned IPs with a positive remaining timeout.
	entries, err := fw.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := map[string]bool{}
	for _, e := range entries {
		switch e.IP {
		case "203.0.113.7", "2001:db8::dead":
			found[e.IP] = true
			if e.Expires <= 0 || e.Expires > time.Minute {
				t.Errorf("unexpected expires for %s: %v", e.IP, e.Expires)
			}
		}
	}
	for _, ip := range []string{"203.0.113.7", "2001:db8::dead"} {
		if !found[ip] {
			t.Errorf("List did not return banned IP %s: %+v", ip, entries)
		}
	}
	// Unban the v6 entry and confirm it is gone.
	if err := fw.Unban("2001:db8::dead"); err != nil {
		t.Fatalf("Unban v6: %v", err)
	}
	entries, err = fw.List(context.Background())
	if err != nil {
		t.Fatalf("List after unban: %v", err)
	}
	for _, e := range entries {
		if e.IP == "2001:db8::dead" {
			t.Errorf("v6 entry still present after Unban: %+v", entries)
		}
	}
	if err := fw.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
}
