// Command simple-blocker watches log sources for malicious probes and bans
// offending IPs through a firewall backend (ipset+iptables or nftables).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"code.sadeq.uk/simple-blocker/internal/blocker"
	"code.sadeq.uk/simple-blocker/internal/config"
	"code.sadeq.uk/simple-blocker/internal/control"
	"code.sadeq.uk/simple-blocker/internal/firewall"
	"code.sadeq.uk/simple-blocker/internal/source"
)

// buildSnapshot assembles the daemon's control-socket snapshot from the live
// firewall set and the offense tracker.
func buildSnapshot(ctx context.Context, fw firewall.Firewall, tracker *blocker.Tracker) (control.Snapshot, error) {
	bans, err := fw.List(ctx)
	if err != nil {
		return control.Snapshot{}, err
	}
	// Start from empty (non-nil) slices so the JSON has [] rather than null.
	snap := control.Snapshot{
		Backend:   fw.Name(),
		Bans:      []control.Ban{},
		Offenders: []control.Offender{},
		TS:        time.Now().UTC().Format(time.RFC3339),
	}
	for _, b := range bans {
		snap.Bans = append(snap.Bans, control.Ban{
			IP:             b.IP,
			ExpiresSeconds: int64(b.Expires.Seconds()),
		})
	}
	for _, o := range tracker.Snapshot() {
		snap.Offenders = append(snap.Offenders, control.Offender{
			IP:              o.IP,
			Count:           o.Count,
			WouldBanSeconds: int64(o.WouldBan.Seconds()),
		})
	}
	return snap, nil
}

// Build metadata, overridden at link time with -X main.version=... etc.
// When built without ldflags, commit/date fall back to the Go VCS stamp.
var (
	version = "dev"
	commit  = ""
	date    = ""
)

// defaultConfigPath is used by every subcommand's -config flag.
const defaultConfigPath = "/etc/simple-blocker/config.yaml"

// overrides holds CLI flags that take precedence over the config file when set.
type overrides struct {
	firewallMode  string
	dockerMode    string
	controlSocket string
}

func main() {
	// Dispatch subcommands on the first argument; anything else (including a
	// leading flag) runs the daemon.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println(versionString())
			return
		case "status":
			if err := cmdStatus(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			return
		case "check":
			if err := cmdCheck(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			return
		case "whitelist", "blacklist":
			if err := cmdList(os.Args[1], os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(1)
			}
			return
		}
	}
	runDaemon()
}

func runDaemon() {
	fs := flag.NewFlagSet("simple-blocker", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to the config file (.yaml, .yml or .json)")
	showVersion := fs.Bool("version", false, "print version information and exit")
	firewallMode := fs.String("firewall-mode", "", "override firewall.mode: internal or external")
	dockerMode := fs.String("docker-mode", "", "override mode for all docker sources: internal or external")
	controlSocket := fs.String("control-socket", "", "override control_socket path")
	_ = fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Println(versionString())
		return
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	slog.Info("simple-blocker", "version", version, "commit", buildCommit(), "date", buildDate())

	if err := run(*configPath, overrides{
		firewallMode:  *firewallMode,
		dockerMode:    *dockerMode,
		controlSocket: *controlSocket,
	}); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// versionString renders the human-readable version line.
func versionString() string {
	return fmt.Sprintf("simple-blocker %s (commit %s, built %s, %s)",
		version, buildCommit(), buildDate(), runtime.Version())
}

// buildCommit returns the linker-provided commit, falling back to the VCS
// revision embedded by the Go toolchain (`go build` without ldflags).
func buildCommit() string {
	if commit != "" {
		return commit
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		rev, dirty := "", false
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				dirty = s.Value == "true"
			}
		}
		if rev != "" {
			if len(rev) > 12 {
				rev = rev[:12]
			}
			if dirty {
				rev += "-dirty"
			}
			return rev
		}
	}
	return "unknown"
}

// buildDate returns the linker-provided build date, falling back to the VCS
// commit time embedded by the Go toolchain.
func buildDate() string {
	if date != "" {
		return date
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.time" {
				return s.Value
			}
		}
	}
	return "unknown"
}

func run(configPath string, ov overrides) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	// Apply CLI overrides, then re-validate if any were set.
	applied := false
	if ov.firewallMode != "" {
		cfg.Firewall.Mode = ov.firewallMode
		applied = true
	}
	if ov.dockerMode != "" {
		for i := range cfg.Sources {
			if cfg.Sources[i].Type == "docker" {
				cfg.Sources[i].Mode = ov.dockerMode
			}
		}
		applied = true
	}
	if ov.controlSocket != "" {
		cfg.ControlSocket = ov.controlSocket
	}
	if applied {
		if err := cfg.Validate(); err != nil {
			return err
		}
	}

	fw, err := firewall.New(cfg.Firewall.Mode, cfg.Firewall.Backend, firewall.Config{
		SetName: cfg.IPSetName,
		Chains:  cfg.Firewall.Chains,
	})
	if err != nil {
		return err
	}

	sources := make([]source.Source, 0, len(cfg.Sources))
	for _, sc := range cfg.Sources {
		s, err := source.New(sc)
		if err != nil {
			return err
		}
		sources = append(sources, s)
	}

	slog.Info("starting", "firewall", fw.Name(), "mode", cfg.Firewall.Mode,
		"set", cfg.IPSetName, "window", cfg.Window, "sources", len(sources))
	if err := fw.Setup(); err != nil {
		return err
	}

	// Remove the firewall rules on shutdown; the ban set is kept intact.
	defer func() {
		if err := fw.Teardown(); err != nil {
			slog.Error("teardown failed", "err", err)
		}
	}()

	white, black, err := cfg.IPLists()
	if err != nil {
		return err
	}

	tracker := blocker.NewTracker(cfg.Window.Duration(), cfg.BanSchedule)
	engine := blocker.NewEngine(tracker, fw, white, black)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Hot-reload the whitelist/blacklist when the config file changes. Only the
	// lists are applied live; other field changes still require a restart. A bad
	// reload is logged and the current lists are kept (fail-safe).
	go func() {
		if err := config.Watch(ctx, configPath, func() {
			ncfg, err := config.Load(configPath)
			if err != nil {
				slog.Error("config reload failed, keeping current lists", "err", err)
				return
			}
			nw, nb, err := ncfg.IPLists()
			if err != nil {
				slog.Error("config reload: bad list entry, keeping current lists", "err", err)
				return
			}
			engine.SetLists(nw, nb)
			slog.Info("config lists reloaded",
				"whitelist", len(ncfg.Whitelist), "blacklist", len(ncfg.Blacklist))
		}); err != nil && ctx.Err() == nil {
			slog.Warn("config watch unavailable", "err", err)
		}
	}()

	// Serve live status on the control socket (read-only) for the `status`
	// command. Failure to listen is non-fatal — the daemon still bans.
	go func() {
		if err := control.Serve(ctx, cfg.ControlSocket, func(ctx context.Context) (control.Snapshot, error) {
			return buildSnapshot(ctx, fw, tracker)
		}); err != nil {
			slog.Warn("control socket unavailable", "err", err)
		}
	}()

	var wg sync.WaitGroup
	for _, s := range sources {
		wg.Add(1)
		go func(s source.Source) {
			defer wg.Done()
			if err := s.Run(ctx, engine.Report); err != nil && ctx.Err() == nil {
				slog.Error("source stopped", "source", s.Name(), "err", err)
			}
		}(s)
	}

	<-ctx.Done()
	slog.Info("shutdown signal received, cleaning up")

	// Give sources a moment to unwind before tearing down rules.
	waitWithTimeout(&wg, 5*time.Second)
	return nil
}

func waitWithTimeout(wg *sync.WaitGroup, d time.Duration) {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}
