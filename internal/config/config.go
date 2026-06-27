// Package config loads simple-blocker's configuration from YAML or JSON.
//
// The format is chosen by file extension: .yaml/.yml are parsed as YAML,
// .json as JSON. Both map onto the same Config struct, so the two formats
// are interchangeable.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration document.
type Config struct {
	// IPSetName is the name of the ipset / nftables set holding banned IPs.
	IPSetName string `yaml:"ipset_name" json:"ipset_name"`
	// Window is the sliding window over which offenses are counted.
	Window Duration `yaml:"window" json:"window"`
	// BanSchedule maps an offense count threshold to a ban duration.
	BanSchedule BanSchedule `yaml:"ban_schedule" json:"ban_schedule"`
	// Firewall configures which backend enforces the bans.
	Firewall Firewall `yaml:"firewall" json:"firewall"`
	// Sources is the list of log sources to monitor.
	Sources []Source `yaml:"sources" json:"sources"`
}

// Firewall configures the enforcement backend.
type Firewall struct {
	// Backend selects the firewall implementation: "auto" (default),
	// "iptables", or "nftables".
	Backend string `yaml:"backend" json:"backend"`
	// Chains lists the iptables chains to insert the DROP rule into
	// (e.g. INPUT, DOCKER-USER). Ignored by the nftables backend.
	Chains []string `yaml:"chains" json:"chains"`
}

// Source describes a single log source to tail for offenders.
type Source struct {
	// Type selects the source implementation: "docker" or "journal".
	Type string `yaml:"type" json:"type"`
	// Name is a human-readable label used in logs.
	Name string `yaml:"name" json:"name"`
	// Target is the container name (docker) or systemd unit (journal).
	Target string `yaml:"target" json:"target"`
	// Pattern is a regular expression with a named capture group "ip"
	// that extracts the offending address from a matching log line.
	Pattern string `yaml:"pattern" json:"pattern"`
	// Since limits how far back a journal source reads (e.g. "-1d").
	// Ignored by non-journal sources. Defaults to "-1d".
	Since string `yaml:"since" json:"since"`
}

// BanTier maps a minimum offense count to a ban duration.
type BanTier struct {
	Offenses int      `yaml:"offenses" json:"offenses"`
	Ban      Duration `yaml:"ban" json:"ban"`
}

// BanSchedule is a set of escalating ban tiers, sorted by offense count.
type BanSchedule []BanTier

// DurationFor returns the ban duration for the given offense count: the
// duration of the highest tier whose threshold the count meets. It returns
// 0 (no ban) when the count is below the lowest tier.
func (s BanSchedule) DurationFor(count int) time.Duration {
	var d time.Duration
	for _, tier := range s {
		if count >= tier.Offenses {
			d = tier.Ban.Duration()
		}
	}
	return d
}

// Duration is a time.Duration that unmarshals from a Go duration string
// (e.g. "3h", "10m", "24h") in both YAML and JSON.
type Duration time.Duration

// Duration returns the underlying time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return time.Duration(d).String() }

func parseDuration(s string) (Duration, error) {
	v, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}
	return Duration(v), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	v, err := parseDuration(s)
	if err != nil {
		return err
	}
	*d = v
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := parseDuration(s)
	if err != nil {
		return err
	}
	*d = v
	return nil
}

// MarshalYAML implements yaml.Marshaler so round-trips stay human-readable.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// Load reads and parses a configuration file, choosing the format from its
// extension, then applies defaults and validates the result.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(data, filepath.Ext(path))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes config bytes using the format implied by ext (".yaml",
// ".yml", or ".json"). It applies defaults and validates the result.
func Parse(data []byte, ext string) (*Config, error) {
	var cfg Config
	switch strings.ToLower(ext) {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, err
		}
	case ".json":
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported config extension %q (use .yaml, .yml or .json)", ext)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.IPSetName == "" {
		c.IPSetName = "simple_blacklist"
	}
	if c.Window == 0 {
		c.Window = Duration(3 * time.Hour)
	}
	if c.Firewall.Backend == "" {
		c.Firewall.Backend = "auto"
	}
	if len(c.Firewall.Chains) == 0 {
		c.Firewall.Chains = []string{"INPUT"}
	}
	for i := range c.Sources {
		if c.Sources[i].Since == "" {
			c.Sources[i].Since = "-1d"
		}
	}
	// Keep the schedule sorted so DurationFor's "highest tier wins" holds.
	sort.SliceStable(c.BanSchedule, func(i, j int) bool {
		return c.BanSchedule[i].Offenses < c.BanSchedule[j].Offenses
	})
}

// Validate checks that the configuration is internally consistent.
func (c *Config) Validate() error {
	switch c.Firewall.Backend {
	case "auto", "iptables", "nftables":
	default:
		return fmt.Errorf("firewall.backend must be auto, iptables or nftables, got %q", c.Firewall.Backend)
	}
	if len(c.BanSchedule) == 0 {
		return fmt.Errorf("ban_schedule must define at least one tier")
	}
	for _, t := range c.BanSchedule {
		if t.Offenses < 1 {
			return fmt.Errorf("ban_schedule offenses must be >= 1, got %d", t.Offenses)
		}
		if t.Ban.Duration() <= 0 {
			return fmt.Errorf("ban_schedule ban duration must be > 0 for offenses=%d", t.Offenses)
		}
	}
	if len(c.Sources) == 0 {
		return fmt.Errorf("at least one source must be configured")
	}
	for i, s := range c.Sources {
		if s.Type != "docker" && s.Type != "journal" {
			return fmt.Errorf("sources[%d]: type must be docker or journal, got %q", i, s.Type)
		}
		if s.Target == "" {
			return fmt.Errorf("sources[%d]: target is required", i)
		}
		if s.Pattern == "" {
			return fmt.Errorf("sources[%d]: pattern is required", i)
		}
	}
	return nil
}
