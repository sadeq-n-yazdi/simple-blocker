package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const yamlFixture = `# top comment
ipset_name: simple_blacklist
# the whitelist below is sacred
whitelist:
  - 10.0.0.5
ban_schedule:
  - { offenses: 2, ban: 10m }
sources:
  - type: journal
    target: ssh
    pattern: 'x(?P<ip>y)'
`

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestYAMLAddPreservesComments(t *testing.T) {
	p := writeTemp(t, "config.yaml", yamlFixture)
	if err := AddListEntry(p, "whitelist", "192.168.0.0/24"); err != nil {
		t.Fatalf("AddListEntry: %v", err)
	}
	out, _ := os.ReadFile(p)
	s := string(out)
	if !strings.Contains(s, "the whitelist below is sacred") {
		t.Errorf("comment not preserved:\n%s", s)
	}
	if !strings.Contains(s, "192.168.0.0/24") || !strings.Contains(s, "10.0.0.5") {
		t.Errorf("entries missing:\n%s", s)
	}
	// It must still parse and carry both entries.
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(cfg.Whitelist) != 2 {
		t.Errorf("whitelist = %v, want 2 entries", cfg.Whitelist)
	}
}

func TestYAMLAddDuplicateIsNoop(t *testing.T) {
	p := writeTemp(t, "config.yaml", yamlFixture)
	before, _ := os.ReadFile(p)
	if err := AddListEntry(p, "whitelist", "10.0.0.5"); err != nil {
		t.Fatalf("AddListEntry: %v", err)
	}
	after, _ := os.ReadFile(p)
	if string(before) != string(after) {
		t.Errorf("duplicate add modified the file:\n%s", after)
	}
}

func TestYAMLAddCreatesAbsentKey(t *testing.T) {
	p := writeTemp(t, "config.yaml", yamlFixture)
	if err := AddListEntry(p, "blacklist", "203.0.113.0/24"); err != nil {
		t.Fatalf("AddListEntry: %v", err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(cfg.Blacklist) != 1 || cfg.Blacklist[0] != "203.0.113.0/24" {
		t.Errorf("blacklist = %v", cfg.Blacklist)
	}
}

func TestYAMLRemove(t *testing.T) {
	p := writeTemp(t, "config.yaml", yamlFixture)
	removed, err := RemoveListEntry(p, "whitelist", "10.0.0.5")
	if err != nil || !removed {
		t.Fatalf("RemoveListEntry: removed=%v err=%v", removed, err)
	}
	cfg, _ := Load(p)
	if len(cfg.Whitelist) != 0 {
		t.Errorf("whitelist = %v, want empty", cfg.Whitelist)
	}
	// Removing again reports not-removed.
	removed, err = RemoveListEntry(p, "whitelist", "10.0.0.5")
	if err != nil || removed {
		t.Errorf("second remove: removed=%v err=%v", removed, err)
	}
}

func TestAddRejectsBadSpec(t *testing.T) {
	p := writeTemp(t, "config.yaml", yamlFixture)
	if err := AddListEntry(p, "whitelist", "not-an-ip"); err == nil {
		t.Error("expected error for bad spec")
	}
}

const jsonFixture = `{
  "ipset_name": "simple_blacklist",
  "blacklist": ["1.1.1.1"],
  "ban_schedule": [{"offenses": 2, "ban": "10m"}],
  "sources": [{"type": "journal", "target": "ssh", "pattern": "x(?P<ip>y)"}]
}
`

func TestJSONRoundTrip(t *testing.T) {
	p := writeTemp(t, "config.json", jsonFixture)
	if err := AddListEntry(p, "blacklist", "2.2.2.2"); err != nil {
		t.Fatalf("AddListEntry: %v", err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(cfg.Blacklist) != 2 {
		t.Errorf("blacklist = %v, want 2", cfg.Blacklist)
	}
	removed, err := RemoveListEntry(p, "blacklist", "1.1.1.1")
	if err != nil || !removed {
		t.Fatalf("remove: removed=%v err=%v", removed, err)
	}
	cfg, _ = Load(p)
	if len(cfg.Blacklist) != 1 || cfg.Blacklist[0] != "2.2.2.2" {
		t.Errorf("blacklist = %v", cfg.Blacklist)
	}
}
