// Command simple-blocker watches log sources for malicious probes and bans
// offending IPs through a firewall backend (ipset+iptables or nftables).
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"code.sadeq.uk/simple-blocker/internal/blocker"
	"code.sadeq.uk/simple-blocker/internal/config"
	"code.sadeq.uk/simple-blocker/internal/firewall"
	"code.sadeq.uk/simple-blocker/internal/source"
)

func main() {
	configPath := flag.String("config", "/etc/simple-blocker/config.yaml", "path to the config file (.yaml, .yml or .json)")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	if err := run(*configPath); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	fw, err := firewall.New(cfg.Firewall.Backend, firewall.Config{
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

	slog.Info("starting", "backend", fw.Name(), "set", cfg.IPSetName,
		"window", cfg.Window, "sources", len(sources))
	if err := fw.Setup(); err != nil {
		return err
	}

	// Remove the firewall rules on shutdown; the ban set is kept intact.
	defer func() {
		if err := fw.Teardown(); err != nil {
			slog.Error("teardown failed", "err", err)
		}
	}()

	engine := blocker.NewEngine(blocker.NewTracker(cfg.Window.Duration(), cfg.BanSchedule), fw)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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
