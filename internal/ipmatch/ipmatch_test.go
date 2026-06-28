package ipmatch

import "testing"

func TestContains(t *testing.T) {
	specs := []string{
		"203.0.113.4",               // single v4
		"2001:db8::1",               // single v6
		"10.0.0.0/24",               // CIDR v4
		"2001:db8:abcd::/48",        // CIDR v6
		"192.168.1.10-192.168.1.40", // range v4
		"fd00::10-fd00::20",         // range v6
		"::ffff:198.51.100.7",       // v4-in-v6 single, normalizes to v4
	}
	l, err := New(specs)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tests := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.4", true},
		{"203.0.113.5", false},
		{"2001:db8::1", true},
		{"2001:db8::2", false},
		{"10.0.0.0", true},
		{"10.0.0.255", true},
		{"10.0.1.0", false},
		{"2001:db8:abcd:1234::1", true},
		{"2001:db8:abce::1", false},
		{"192.168.1.10", true}, // low boundary
		{"192.168.1.40", true}, // high boundary
		{"192.168.1.9", false},
		{"192.168.1.41", false},
		{"fd00::10", true},
		{"fd00::20", true},
		{"fd00::21", false},
		{"198.51.100.7", true},       // matches the v4-in-v6 single
		{"::ffff:203.0.113.4", true}, // queried as v4-in-v6, matches plain v4 single
		{"not-an-ip", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := l.Contains(tc.ip); got != tc.want {
			t.Errorf("Contains(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestNewErrors(t *testing.T) {
	bad := []string{
		"not-an-ip",
		"10.0.0.0/99",
		"1.2.3.4-",
		"1.2.3.4-nope",
		"192.168.1.40-192.168.1.10", // hi < lo
		"10.0.0.1-2001:db8::1",      // mismatched family
	}
	for _, spec := range bad {
		if _, err := New([]string{spec}); err == nil {
			t.Errorf("New(%q): expected error, got nil", spec)
		}
		if err := ParseSpec(spec); err == nil {
			t.Errorf("ParseSpec(%q): expected error, got nil", spec)
		}
	}
}

func TestParseSpecValid(t *testing.T) {
	good := []string{"1.2.3.4", "10.0.0.0/8", "1.1.1.1-1.1.1.9", "2001:db8::/32"}
	for _, spec := range good {
		if err := ParseSpec(spec); err != nil {
			t.Errorf("ParseSpec(%q): unexpected error %v", spec, err)
		}
	}
}

func TestEmptyAndNil(t *testing.T) {
	var nilList *List
	if !nilList.Empty() {
		t.Error("nil list should be Empty")
	}
	if nilList.Contains("1.2.3.4") {
		t.Error("nil list should not Contain anything")
	}
	empty, _ := New([]string{"  ", ""})
	if !empty.Empty() {
		t.Error("whitespace-only specs should yield an empty list")
	}
}
