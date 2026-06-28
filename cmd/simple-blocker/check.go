package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"code.sadeq.uk/simple-blocker/internal/blocker"
	"code.sadeq.uk/simple-blocker/internal/config"
	"code.sadeq.uk/simple-blocker/internal/source"
)

const (
	ansiHighlight = "\x1b[1;31m" // bold red
	ansiReset     = "\x1b[0m"
)

// cmdCheck implements `simple-blocker check`: scan logs, print each line that
// matches a configured pattern with the IP highlighted, and (by default) the
// action the daemon would take, simulated against the ban schedule.
func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to the config file")
	follow := fs.Bool("follow", false, "stream logs live instead of reading recent history")
	srcName := fs.String("source", "", "only check the named source (default: all)")
	colorMode := fs.String("color", "auto", "colorize the IP: auto|always|never")
	showActions := fs.Bool("actions", true, "print the action that would be taken for each match")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	sources := selectSources(cfg.Sources, *srcName)
	if len(sources) == 0 {
		return fmt.Errorf("no matching sources (have %d configured)", len(cfg.Sources))
	}
	color := useColor(*colorMode)

	// A single dry-run tracker so the simulated offense counts escalate just
	// like the daemon's would. Nothing is banned.
	tracker := blocker.NewTracker(cfg.Window.Duration(), cfg.BanSchedule)
	lowest := lowestThreshold(cfg.BanSchedule)
	window := cfg.Window.Duration()

	var mu sync.Mutex // serialize output across concurrent sources
	onMatch := func(m source.Match) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Printf("[%s] %s\n", m.Source, highlight(m, color))
		// Skip the action when the IP group didn't participate (m.IP == ""),
		// otherwise we'd simulate offenses for the empty string.
		if !*showActions || m.IP == "" {
			return
		}
		ban, count := tracker.Record(m.IP)
		if ban > 0 {
			fmt.Printf("    → offense #%d from %s within %s → would ban %s\n", count, m.IP, window, ban)
		} else {
			fmt.Printf("    → offense #%d from %s → no ban yet (bans start at #%d)\n", count, m.IP, lowest)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *follow {
		return scanConcurrent(ctx, sources, onMatch)
	}
	// Recent history: read each source sequentially so escalation is deterministic.
	for _, c := range sources {
		if ctx.Err() != nil {
			break // cancelled (Ctrl-C): don't run the remaining sources
		}
		if err := source.Scan(ctx, c, false, onMatch); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "source %q: %v\n", label(c), err)
		}
	}
	return nil
}

func scanConcurrent(ctx context.Context, sources []config.Source, onMatch func(source.Match)) error {
	var wg sync.WaitGroup
	for _, c := range sources {
		wg.Add(1)
		go func(c config.Source) {
			defer wg.Done()
			if err := source.Scan(ctx, c, true, onMatch); err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "source %q: %v\n", label(c), err)
			}
		}(c)
	}
	wg.Wait()
	return nil
}

func selectSources(all []config.Source, name string) []config.Source {
	if name == "" {
		return all
	}
	var out []config.Source
	for _, c := range all {
		if c.Name == name || c.Target == name {
			out = append(out, c)
		}
	}
	return out
}

func label(c config.Source) string {
	if c.Name != "" {
		return c.Name
	}
	return c.Target
}

func lowestThreshold(s config.BanSchedule) int {
	if len(s) == 0 {
		return 0
	}
	lo := s[0].Offenses
	for _, t := range s {
		if t.Offenses < lo {
			lo = t.Offenses
		}
	}
	return lo
}

// highlight wraps the captured IP span in ANSI color when enabled.
func highlight(m source.Match, color bool) string {
	if !color || m.IPStart < 0 || m.IPEnd > len(m.Line) || m.IPStart >= m.IPEnd {
		return m.Line
	}
	return m.Line[:m.IPStart] + ansiHighlight + m.Line[m.IPStart:m.IPEnd] + ansiReset + m.Line[m.IPEnd:]
}

func useColor(mode string) bool {
	switch mode {
	case "always":
		return true
	case "never":
		return false
	default: // auto
		if os.Getenv("NO_COLOR") != "" {
			return false
		}
		fi, err := os.Stdout.Stat()
		return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
	}
}
