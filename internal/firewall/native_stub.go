//go:build !linux

package firewall

import "fmt"

// newNative is unavailable off Linux: nftables/netlink is Linux-only. The stub
// keeps the package buildable on other platforms (e.g. macOS dev machines).
func newNative(cfg Config) (Firewall, error) {
	return nil, fmt.Errorf("internal (nftables-native) firewall is only supported on Linux; use firewall.mode: external")
}
