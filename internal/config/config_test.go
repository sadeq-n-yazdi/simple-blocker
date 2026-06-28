package config

import (
	"fmt"
	"testing"
	"time"
)

func TestParseYAML(t *testing.T) {
	data := []byte(`
ipset_name: bl
window: 2h
firewall:
  backend: iptables
  chains: [INPUT, DOCKER-USER]
ban_schedule:
  - { offenses: 5, ban: 1h }
  - { offenses: 2, ban: 10m }
sources:
  - type: journal
    target: ssh
    pattern: 'from (?P<ip>\d+)'
`)
	cfg, err := Parse(data, ".yaml")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.IPSetName != "bl" {
		t.Errorf("IPSetName = %q", cfg.IPSetName)
	}
	if cfg.Window.Duration() != 2*time.Hour {
		t.Errorf("Window = %v", cfg.Window)
	}
	// applyDefaults must sort the schedule ascending.
	if cfg.BanSchedule[0].Offenses != 2 || cfg.BanSchedule[1].Offenses != 5 {
		t.Errorf("schedule not sorted: %+v", cfg.BanSchedule)
	}
	// journal source gets the default "since".
	if cfg.Sources[0].Since != "-1d" {
		t.Errorf("Since default = %q", cfg.Sources[0].Since)
	}
}

func TestParseJSONEquivalentToYAML(t *testing.T) {
	js := []byte(`{
		"window": "30m",
		"ban_schedule": [{"offenses": 1, "ban": "5m"}],
		"sources": [{"type": "docker", "target": "c", "pattern": "(?P<ip>x)"}]
	}`)
	cfg, err := Parse(js, ".json")
	if err != nil {
		t.Fatalf("Parse json: %v", err)
	}
	if cfg.Window.Duration() != 30*time.Minute {
		t.Errorf("Window = %v", cfg.Window)
	}
	// Defaults applied to JSON too.
	if cfg.IPSetName != "simple_blacklist" {
		t.Errorf("default IPSetName = %q", cfg.IPSetName)
	}
	if cfg.Firewall.Backend != "auto" {
		t.Errorf("default backend = %q", cfg.Firewall.Backend)
	}
	if cfg.Firewall.Mode != "internal" {
		t.Errorf("default firewall mode = %q, want internal", cfg.Firewall.Mode)
	}
}

func TestFirewallModeValidation(t *testing.T) {
	base := `{"firewall":{"mode":%q},"ban_schedule":[{"offenses":1,"ban":"5m"}],"sources":[{"type":"docker","target":"c","pattern":"(?P<ip>x)"}]}`
	if _, err := Parse([]byte(`{"firewall":{"mode":"sideways"},"ban_schedule":[{"offenses":1,"ban":"5m"}],"sources":[{"type":"docker","target":"c","pattern":"x"}]}`), ".json"); err == nil {
		t.Fatal("expected error for invalid firewall.mode")
	}
	for _, mode := range []string{"internal", "external"} {
		doc := []byte(fmt.Sprintf(base, mode))
		if _, err := Parse(doc, ".json"); err != nil {
			t.Errorf("mode %q should be valid: %v", mode, err)
		}
	}
}

func TestParseUnsupportedExt(t *testing.T) {
	if _, err := Parse([]byte(`{}`), ".toml"); err == nil {
		t.Fatal("expected error for unsupported extension")
	}
}

func TestValidate(t *testing.T) {
	cases := map[string]string{
		"bad backend":     `{"firewall":{"backend":"pf"},"ban_schedule":[{"offenses":1,"ban":"5m"}],"sources":[{"type":"docker","target":"c","pattern":"x"}]}`,
		"empty schedule":  `{"sources":[{"type":"docker","target":"c","pattern":"x"}]}`,
		"bad source type": `{"ban_schedule":[{"offenses":1,"ban":"5m"}],"sources":[{"type":"syslog","target":"c","pattern":"x"}]}`,
		"missing target":  `{"ban_schedule":[{"offenses":1,"ban":"5m"}],"sources":[{"type":"docker","pattern":"x"}]}`,
		"zero ban":        `{"ban_schedule":[{"offenses":1,"ban":"0s"}],"sources":[{"type":"docker","target":"c","pattern":"x"}]}`,
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc), ".json"); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestDurationForHighestTierWins(t *testing.T) {
	s := BanSchedule{
		{Offenses: 2, Ban: Duration(10 * time.Minute)},
		{Offenses: 3, Ban: Duration(30 * time.Minute)},
		{Offenses: 5, Ban: Duration(time.Hour)},
		{Offenses: 7, Ban: Duration(24 * time.Hour)},
	}
	tests := []struct {
		count int
		want  time.Duration
	}{
		{1, 0},
		{2, 10 * time.Minute},
		{4, 30 * time.Minute}, // 4th offense falls into the 3-tier
		{5, time.Hour},
		{6, time.Hour},
		{9, 24 * time.Hour},
	}
	for _, tt := range tests {
		if got := s.DurationFor(tt.count); got != tt.want {
			t.Errorf("DurationFor(%d) = %v, want %v", tt.count, got, tt.want)
		}
	}
}

func TestSourceModeDefaults(t *testing.T) {
	js := []byte(`{
		"ban_schedule": [{"offenses": 1, "ban": "5m"}],
		"sources": [
			{"type": "docker", "target": "c", "pattern": "(?P<ip>x)"},
			{"type": "journal", "target": "ssh", "pattern": "(?P<ip>x)"}
		]
	}`)
	cfg, err := Parse(js, ".json")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Sources[0].Mode != "internal" {
		t.Errorf("docker default mode = %q, want internal", cfg.Sources[0].Mode)
	}
	if cfg.Sources[1].Mode != "external" {
		t.Errorf("journal default mode = %q, want external", cfg.Sources[1].Mode)
	}
}

func TestSourceModeValidation(t *testing.T) {
	cases := map[string]string{
		"journal internal": `{"ban_schedule":[{"offenses":1,"ban":"5m"}],"sources":[{"type":"journal","target":"ssh","mode":"internal","pattern":"(?P<ip>x)"}]}`,
		"bad mode":         `{"ban_schedule":[{"offenses":1,"ban":"5m"}],"sources":[{"type":"docker","target":"c","mode":"sideways","pattern":"(?P<ip>x)"}]}`,
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc), ".json"); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestDockerHostRoundTrip(t *testing.T) {
	js := []byte(`{"ban_schedule":[{"offenses":1,"ban":"5m"}],"sources":[{"type":"docker","target":"c","docker_host":"/run/docker.sock","pattern":"(?P<ip>x)"}]}`)
	cfg, err := Parse(js, ".json")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Sources[0].DockerHost != "/run/docker.sock" {
		t.Errorf("docker_host = %q", cfg.Sources[0].DockerHost)
	}
}

func TestBadDuration(t *testing.T) {
	if _, err := Parse([]byte(`{"window":"banana","ban_schedule":[{"offenses":1,"ban":"5m"}],"sources":[{"type":"docker","target":"c","pattern":"x"}]}`), ".json"); err == nil {
		t.Fatal("expected error for bad duration")
	}
}
