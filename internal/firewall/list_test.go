package firewall

import (
	"testing"
	"time"
)

func TestParseIPSetList(t *testing.T) {
	out := `Name: simple_blacklist
Type: hash:ip
Revision: 5
Header: family inet hashsize 1024 maxelem 65536 timeout 0
Size in memory: 200
References: 2
Number of entries: 2
Members:
1.2.3.4 timeout 59
5.6.7.8 timeout 3540
`
	got := parseIPSetList(out)
	if len(got) != 2 {
		t.Fatalf("got %d entries: %+v", len(got), got)
	}
	if got[0].IP != "1.2.3.4" || got[0].Expires != 59*time.Second {
		t.Errorf("entry0 = %+v", got[0])
	}
	if got[1].IP != "5.6.7.8" || got[1].Expires != 3540*time.Second {
		t.Errorf("entry1 = %+v", got[1])
	}
}

func TestParseIPSetListNoTimeout(t *testing.T) {
	out := "Name: x\nMembers:\n9.9.9.9\n"
	got := parseIPSetList(out)
	if len(got) != 1 || got[0].IP != "9.9.9.9" || got[0].Expires != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestParseNFTSetJSON(t *testing.T) {
	// Mixed: one element with timeout/expires, one bare string.
	out := `{"nftables":[
		{"metainfo":{"version":"1.0.6"}},
		{"set":{"family":"inet","name":"simple_blacklist","table":"simple_blocker",
			"elem":[
				{"elem":{"val":"1.2.3.4","timeout":600,"expires":540}},
				"5.6.7.8"
			]}}
	]}`
	got, err := parseNFTSetJSON(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d: %+v", len(got), got)
	}
	if got[0].IP != "1.2.3.4" || got[0].Expires != 540*time.Second {
		t.Errorf("entry0 = %+v", got[0])
	}
	if got[1].IP != "5.6.7.8" || got[1].Expires != 0 {
		t.Errorf("entry1 = %+v", got[1])
	}
}

func TestParseNFTSetJSONEmpty(t *testing.T) {
	out := `{"nftables":[{"set":{"name":"x"}}]}`
	got, err := parseNFTSetJSON(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no entries, got %+v", got)
	}
}

// TestListViaRunner exercises List() through the injectable runner for the exec
// backends, confirming the right command is issued and output parsed.
func TestIPTablesListViaRunner(t *testing.T) {
	var gotCmd string
	orig := runner
	t.Cleanup(func() { runner = orig })
	runner = func(name string, args ...string) (string, error) {
		gotCmd = name + " " + args[0]
		return "Members:\n1.1.1.1 timeout 10\n", nil
	}
	fw := newIPTables(Config{SetName: "bl"})
	entries, err := fw.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if gotCmd != "ipset list" {
		t.Errorf("command = %q", gotCmd)
	}
	if len(entries) != 1 || entries[0].IP != "1.1.1.1" {
		t.Errorf("entries = %+v", entries)
	}
}
