package firewall

import "net/netip"

// v6SetName derives the IPv6 set name from the IPv4 set name by appending "6"
// (e.g. simple_blacklist -> simple_blacklist6). Keeping it derived avoids a
// second config field; the result stays within ipset's 31-char name limit for
// any reasonable base name.
func v6SetName(base string) string { return base + "6" }

// isIPv6 reports whether ip is an IPv6 address that must be enforced through the
// v6 path. An IPv4-in-IPv6 mapping (::ffff:a.b.c.d) is treated as IPv4. ok is
// false when ip does not parse as an address at all.
func isIPv6(ip string) (v6, ok bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false, false
	}
	addr = addr.Unmap()
	return addr.Is6(), true
}
