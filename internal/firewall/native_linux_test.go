//go:build linux

package firewall

import (
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
	fw, err := New("internal", "", Config{SetName: "sb_test_set"})
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
	if err := fw.Teardown(); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
}
