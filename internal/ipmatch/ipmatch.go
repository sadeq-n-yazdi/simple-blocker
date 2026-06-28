// Package ipmatch matches an IP address against a list of specifications.
//
// Each spec is one of:
//   - a single address — "203.0.113.4" or "2001:db8::1"
//   - an inclusive range — "192.168.1.10-192.168.1.40" (FROM-TO, same family)
//   - a CIDR block — "10.0.0.0/24" or "2001:db8::/32"
//
// Matching works uniformly for IPv4 and IPv6 via net/netip. Addresses are
// normalized with Unmap so a v4-in-v6 form compares equal to its plain v4 form.
package ipmatch

import (
	"fmt"
	"net/netip"
	"strings"
)

// kind distinguishes the three entry shapes.
type kind int

const (
	kindSingle kind = iota
	kindPrefix
	kindRange
)

// entry is one parsed spec.
type entry struct {
	kind   kind
	addr   netip.Addr   // kindSingle
	prefix netip.Prefix // kindPrefix
	lo, hi netip.Addr   // kindRange
}

// List is a parsed, ordered set of specs. The zero value (and a nil *List)
// matches nothing. List is read-only after New, so it is safe to share a
// *List across goroutines.
type List struct {
	entries []entry
}

// New parses each spec into a List. It returns an error naming the first spec
// that fails to parse. Empty/whitespace-only specs are skipped.
func New(specs []string) (*List, error) {
	l := &List{}
	for _, raw := range specs {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		e, err := parse(s)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", s, err)
		}
		l.entries = append(l.entries, e)
	}
	return l, nil
}

// ParseSpec validates a single spec, returning an error if it is malformed. It
// is used to reject a bad entry before writing it to the config file.
func ParseSpec(spec string) error {
	s := strings.TrimSpace(spec)
	if s == "" {
		return fmt.Errorf("empty spec")
	}
	_, err := parse(s)
	return err
}

func parse(s string) (entry, error) {
	switch {
	case strings.Contains(s, "/"):
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return entry{}, fmt.Errorf("invalid CIDR: %w", err)
		}
		return entry{kind: kindPrefix, prefix: p.Masked()}, nil
	case strings.Contains(s, "-"):
		loStr, hiStr, ok := strings.Cut(s, "-")
		if !ok {
			return entry{}, fmt.Errorf("invalid range")
		}
		lo, err := netip.ParseAddr(strings.TrimSpace(loStr))
		if err != nil {
			return entry{}, fmt.Errorf("invalid range start: %w", err)
		}
		hi, err := netip.ParseAddr(strings.TrimSpace(hiStr))
		if err != nil {
			return entry{}, fmt.Errorf("invalid range end: %w", err)
		}
		lo, hi = lo.Unmap(), hi.Unmap()
		if lo.Is4() != hi.Is4() {
			return entry{}, fmt.Errorf("range endpoints must be the same family")
		}
		if hi.Less(lo) {
			return entry{}, fmt.Errorf("range end is before range start")
		}
		return entry{kind: kindRange, lo: lo, hi: hi}, nil
	default:
		a, err := netip.ParseAddr(s)
		if err != nil {
			return entry{}, fmt.Errorf("invalid address: %w", err)
		}
		return entry{kind: kindSingle, addr: a.Unmap()}, nil
	}
}

// Contains reports whether ip matches any entry. It returns false for an
// unparseable ip and for a nil/empty list.
func (l *List) Contains(ip string) bool {
	if l == nil || len(l.entries) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, e := range l.entries {
		switch e.kind {
		case kindSingle:
			if e.addr == addr {
				return true
			}
		case kindPrefix:
			if e.prefix.Contains(addr) {
				return true
			}
		case kindRange:
			// Same-family guard: Compare orders v4 before v6, so a cross-family
			// addr can't fall inside a same-family range by accident.
			if e.lo.Is4() == addr.Is4() && e.lo.Compare(addr) <= 0 && addr.Compare(e.hi) <= 0 {
				return true
			}
		}
	}
	return false
}

// Empty reports whether the list has no entries.
func (l *List) Empty() bool {
	return l == nil || len(l.entries) == 0
}
