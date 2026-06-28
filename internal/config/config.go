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

	"code.sadeq.uk/simple-blocker/internal/ipmatch"
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
	// ControlSocket is the unix socket the daemon serves live status on, and
	// that the `status` command reads. Defaults to /run/simple-blocker.sock.
	ControlSocket string `yaml:"control_socket" json:"control_socket"`
	// Whitelist holds addresses the daemon must never ban. Blacklist holds
	// addresses banned permanently when they trip a pattern. Whitelist wins.
	// Each entry is a single IP, an inclusive range "FROM-TO", or a CIDR block.
	Whitelist []string `yaml:"whitelist" json:"whitelist"`
	Blacklist []string `yaml:"blacklist" json:"blacklist"`
}

// Firewall configures the enforcement backend.
type Firewall struct {
	// Mode selects the implementation: "internal" (pure-Go nftables over
	// netlink, no external binaries) or "external" (shell out to the host's
	// firewall tools). Defaults to "internal".
	Mode string `yaml:"mode" json:"mode"`
	// Backend selects the external firewall implementation: "auto" (default),
	// "iptables", or "nftables". Only used when Mode is "external".
	Backend string `yaml:"backend" json:"backend"`
	// Chains lists the iptables chains to insert the DROP rule into
	// (e.g. INPUT, DOCKER-USER). Ignored by the nftables backend.
	Chains []string `yaml:"chains" json:"chains"`
	// EnforceIPv6 opts in to banning IPv6 offenders in the firewall. It is off
	// by default: matching (whitelist/blacklist) already handles v6, but actual
	// enforcement adds a parallel v6 set and drop rule, which on some hosts
	// (e.g. Docker without IPv6) needs deliberate enabling. Best-effort: a host
	// that can't establish v6 rules logs and keeps enforcing v4.
	EnforceIPv6 bool `yaml:"enforce_ipv6" json:"enforce_ipv6"`
}

// Source describes a single log source to tail for offenders.
type Source struct {
	// Type selects the source implementation: "docker", "journal", or "file".
	Type string `yaml:"type" json:"type"`
	// Name is a human-readable label used in logs.
	Name string `yaml:"name" json:"name"`
	// Target is the container name (docker), systemd unit (journal), or log
	// file path (file).
	Target string `yaml:"target" json:"target"`
	// Pattern is a regular expression with a named capture group "ip"
	// that extracts the offending address from a matching log line. A file
	// source may also include an optional "ts" group to enable time-window
	// filtering (see Since and TimeFormat).
	Pattern string `yaml:"pattern" json:"pattern"`
	// Since limits how far back a source reads. For journal it is passed to
	// journalctl (e.g. "-1d"). For file it is a lookback (e.g. "-1d", "12h")
	// that skips lines older than the cutoff when the pattern has a "ts" group.
	// Ignored by docker. Defaults to "-1d".
	Since string `yaml:"since" json:"since"`
	// Mode selects the implementation: "internal" (pure-Go Docker Engine API)
	// or "external" (exec `docker logs`). Only meaningful for docker; journal
	// is always external and file does not use it. Defaults to "internal" for docker.
	Mode string `yaml:"mode" json:"mode"`
	// DockerHost overrides the Docker daemon unix socket path for internal
	// docker sources. Defaults to "/var/run/docker.sock". Ignored otherwise.
	DockerHost string `yaml:"docker_host" json:"docker_host"`
	// TimeFormat overrides the timestamp layout for a file source's "ts" group
	// (a Go reference layout, e.g. "02/Jan/2006:15:04:05 -0700"). Optional; when
	// empty a built-in list of common layouts is auto-detected. Only used by file.
	TimeFormat string `yaml:"time_format" json:"time_format"`
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
	if c.ControlSocket == "" {
		c.ControlSocket = "/run/simple-blocker.sock"
	}
	if c.Firewall.Mode == "" {
		c.Firewall.Mode = "internal"
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
		if c.Sources[i].Mode == "" {
			switch c.Sources[i].Type {
			case "docker":
				c.Sources[i].Mode = "internal"
			case "journal":
				c.Sources[i].Mode = "external"
			}
		}
	}
	// Keep the schedule sorted so DurationFor's "highest tier wins" holds.
	sort.SliceStable(c.BanSchedule, func(i, j int) bool {
		return c.BanSchedule[i].Offenses < c.BanSchedule[j].Offenses
	})
}

// IPLists compiles the whitelist and blacklist into matchers. Parse errors are
// wrapped so the offending entry is named. The returned lists are never nil
// (an empty list matches nothing), so callers need not nil-check them.
func (c *Config) IPLists() (white, black *ipmatch.List, err error) {
	white, err = ipmatch.New(c.Whitelist)
	if err != nil {
		return nil, nil, fmt.Errorf("whitelist: %w", err)
	}
	black, err = ipmatch.New(c.Blacklist)
	if err != nil {
		return nil, nil, fmt.Errorf("blacklist: %w", err)
	}
	return white, black, nil
}

// Validate checks that the configuration is internally consistent.
func (c *Config) Validate() error {
	if _, _, err := c.IPLists(); err != nil {
		return err
	}
	switch c.Firewall.Mode {
	case "internal", "external":
	default:
		return fmt.Errorf("firewall.mode must be internal or external, got %q", c.Firewall.Mode)
	}
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
		if s.Type != "docker" && s.Type != "journal" && s.Type != "file" {
			return fmt.Errorf("sources[%d]: type must be docker, journal, or file, got %q", i, s.Type)
		}
		if s.Target == "" {
			return fmt.Errorf("sources[%d]: target is required", i)
		}
		if s.Pattern == "" {
			return fmt.Errorf("sources[%d]: pattern is required", i)
		}
		switch s.Mode {
		case "", "internal", "external":
		default:
			return fmt.Errorf("sources[%d]: mode must be internal or external, got %q", i, s.Mode)
		}
		if s.Type == "journal" && s.Mode == "internal" {
			return fmt.Errorf("sources[%d]: journal source does not support internal mode", i)
		}
		if s.Type == "file" && s.Mode != "" {
			return fmt.Errorf("sources[%d]: file source does not support mode", i)
		}
	}
	return nil
}
