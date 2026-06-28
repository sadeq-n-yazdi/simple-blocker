package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"code.sadeq.uk/simple-blocker/internal/config"
	"code.sadeq.uk/simple-blocker/internal/firewall"
	"code.sadeq.uk/simple-blocker/internal/ipmatch"
)

// cmdList implements `simple-blocker whitelist|blacklist add|remove|show`.
// It edits the config file in place; a running daemon picks the change up via
// its file watcher within a couple of seconds. On removal (and on whitelist
// add) it also lifts any matching live bans from the firewall set.
func cmdList(list string, args []string) error {
	// Handle help in the positional slots before the dispatch consumes them —
	// otherwise `whitelist -h` would be read as an unknown action and
	// `whitelist add -h` would try to add "-h" as a list entry. Only the
	// positionals are checked (action, then the spec for add/remove); a help
	// flag among the trailing flags is left to the flag parser, so a value like
	// `-config help` is not mistaken for a help request.
	if len(args) == 0 {
		// A bare management command shows full help rather than a terse error.
		fmt.Print(listHelp(list))
		return nil
	}
	if isHelpArg(args[0]) {
		fmt.Print(listHelp(list))
		return nil
	}
	if (args[0] == "add" || args[0] == "remove") && len(args) > 1 && isHelpArg(args[1]) {
		fmt.Print(listHelp(list))
		return nil
	}
	action := args[0]
	rest := args[1:]

	// For add/remove the spec is the next positional; flags follow it.
	var spec string
	flagArgs := rest
	if action == "add" || action == "remove" {
		if len(rest) == 0 {
			return fmt.Errorf("usage: simple-blocker %s %s <ip|range|cidr>", list, action)
		}
		spec = rest[0]
		flagArgs = rest[1:]
	}

	fs := flag.NewFlagSet(list, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stdout, listHelp(list)) }
	configPath := fs.String("config", defaultConfigPath, "path to the config file")
	if err := fs.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil // -h after the spec already printed help
		}
		return err
	}

	switch action {
	case "show":
		return showList(list, *configPath)
	case "add":
		if err := config.AddListEntry(*configPath, list, spec); err != nil {
			return err
		}
		fmt.Printf("added %s to %s in %s\n", spec, list, *configPath)
		if list == "whitelist" {
			// Make the whitelist effective immediately by lifting any live bans
			// the new entry now protects.
			liftLiveBans(*configPath, spec)
		}
		fmt.Println("a running daemon will apply the change within a few seconds")
		return nil
	case "remove":
		removed, err := config.RemoveListEntry(*configPath, list, spec)
		if err != nil {
			return err
		}
		if !removed {
			fmt.Printf("%s was not in %s\n", spec, list)
		} else {
			fmt.Printf("removed %s from %s in %s\n", spec, list, *configPath)
		}
		// Lift matching live bans regardless of which list, so removal takes
		// effect now rather than waiting for the ban to expire.
		liftLiveBans(*configPath, spec)
		fmt.Println("a running daemon will apply the change within a few seconds")
		return nil
	default:
		return fmt.Errorf("unknown action %q (use add, remove or show)", action)
	}
}

func showList(list, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	entries := cfg.Whitelist
	if list == "blacklist" {
		entries = cfg.Blacklist
	}
	if len(entries) == 0 {
		fmt.Printf("%s is empty\n", list)
		return nil
	}
	for _, e := range entries {
		fmt.Println(e)
	}
	return nil
}

// liftLiveBans removes every member of the live firewall set that matches spec
// (a single IP, range, or CIDR). It reports what it did. Failures are surfaced
// but not fatal: the config edit already succeeded, and the change still takes
// effect on the daemon's next reload. Needs privileges to reach the firewall.
func liftLiveBans(configPath, spec string) {
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Printf("note: could not reload config to lift live bans: %v\n", err)
		return
	}
	fw, err := firewall.New(cfg.Firewall.Mode, cfg.Firewall.Backend, firewall.Config{
		SetName:     cfg.IPSetName,
		Chains:      cfg.Firewall.Chains,
		EnforceIPv6: cfg.Firewall.EnforceIPv6,
	})
	if err != nil {
		fmt.Printf("note: config updated, but could not open the firewall to lift live bans (try sudo): %v\n", err)
		return
	}
	m, err := ipmatch.New([]string{spec})
	if err != nil {
		return // spec was already validated; defensive only
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bans, err := fw.List(ctx)
	if err != nil {
		fmt.Printf("note: config updated, but could not read the firewall to lift live bans (try sudo): %v\n", err)
		return
	}
	var lifted, failed int
	for _, b := range bans {
		if !m.Contains(b.IP) {
			continue
		}
		if err := fw.Unban(b.IP); err != nil {
			fmt.Printf("note: failed to unban %s: %v\n", b.IP, err)
			failed++
			continue
		}
		lifted++
	}
	if lifted > 0 || failed > 0 {
		fmt.Printf("lifted %d live ban(s) matching %s", lifted, spec)
		if failed > 0 {
			fmt.Printf(" (%d failed)", failed)
		}
		fmt.Println()
	}
}
