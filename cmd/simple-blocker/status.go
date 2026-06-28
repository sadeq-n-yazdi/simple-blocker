package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"code.sadeq.uk/simple-blocker/internal/config"
	"code.sadeq.uk/simple-blocker/internal/control"
	"code.sadeq.uk/simple-blocker/internal/firewall"
)

// cmdStatus implements `simple-blocker status`: show currently-banned IPs and,
// when the daemon is reachable, the offense tracker and the diff between them.
func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	configPath := fs.String("config", defaultConfigPath, "path to the config file")
	socketFlag := fs.String("control-socket", "", "control socket path (overrides config)")
	asJSON := fs.Bool("json", false, "emit the raw snapshot as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	socket := cfg.ControlSocket
	if *socketFlag != "" {
		socket = *socketFlag
	}

	// Prefer the live daemon (full picture); fall back to reading the firewall
	// set directly when it isn't running.
	snap, live, err := fetchStatus(socket, cfg)
	if err != nil {
		return err
	}
	if snap.Error != "" {
		return fmt.Errorf("daemon reported: %s", snap.Error)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(snap)
	}
	renderStatus(os.Stdout, snap, live)
	return nil
}

// fetchStatus returns the snapshot and whether it came from the live daemon.
func fetchStatus(socket string, cfg *config.Config) (control.Snapshot, bool, error) {
	if snap, err := control.Dial(socket); err == nil {
		return snap, true, nil
	}
	// Fallback: read the firewall set directly (needs root). No tracker view.
	fw, err := firewall.New(cfg.Firewall.Mode, cfg.Firewall.Backend, firewall.Config{
		SetName: cfg.IPSetName,
		Chains:  cfg.Firewall.Chains,
	})
	if err != nil {
		return control.Snapshot{}, false, err
	}
	bans, err := fw.List()
	if err != nil {
		return control.Snapshot{}, false, fmt.Errorf("daemon not reachable and reading firewall failed: %w", err)
	}
	snap := control.Snapshot{
		Backend:   fw.Name(),
		Bans:      []control.Ban{},
		Offenders: []control.Offender{},
		TS:        time.Now().UTC().Format(time.RFC3339),
	}
	for _, b := range bans {
		snap.Bans = append(snap.Bans, control.Ban{IP: b.IP, ExpiresSeconds: int64(b.Expires.Seconds())})
	}
	return snap, false, nil
}

func renderStatus(w *os.File, snap control.Snapshot, live bool) {
	bans := map[string]int64{}
	for _, b := range snap.Bans {
		bans[b.IP] = b.ExpiresSeconds
	}
	tracked := map[string]control.Offender{}
	for _, o := range snap.Offenders {
		tracked[o.IP] = o
	}

	fmt.Fprintf(w, "backend: %s   %s\n\n", snap.Backend, sourceNote(live))

	// Banned (firewall).
	fmt.Fprintf(w, "Banned (firewall): %d\n", len(snap.Bans))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  IP\tEXPIRES\tOFFENSES")
	for _, b := range sortedBans(snap.Bans) {
		off := "-"
		if o, ok := tracked[b.IP]; ok {
			off = fmt.Sprintf("%d", o.Count)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", b.IP, humanSeconds(b.ExpiresSeconds), off)
	}
	tw.Flush()

	if !live {
		fmt.Fprintln(w, "\n(daemon not running — offense tracker unavailable)")
		return
	}

	// Offenders (tracker).
	fmt.Fprintf(w, "\nOffenders (tracker): %d\n", len(snap.Offenders))
	tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  IP\tOFFENSES\tWOULD-BAN\tBANNED")
	for _, o := range sortedOffenders(snap.Offenders) {
		_, isBanned := bans[o.IP]
		fmt.Fprintf(tw, "  %s\t%d\t%s\t%v\n", o.IP, o.Count, humanSeconds(o.WouldBanSeconds), isBanned)
	}
	tw.Flush()

	// Diff — the parts worth attention.
	anomalies, lingering, watching := diffStatus(snap)

	fmt.Fprintln(w, "\nDiff:")
	fmt.Fprintf(w, "  over threshold but NOT banned (anomaly): %s\n", joinOrNone(anomalies))
	fmt.Fprintf(w, "  banned but no longer tracked (ban outlives window/restart): %s\n", joinOrNone(lingering))
	fmt.Fprintf(w, "  tracked, under threshold (watching): %s\n", joinOrNone(watching))
}

// diffStatus categorizes the snapshot into the noteworthy buckets:
//   - anomalies: tracked at/over the ban threshold but NOT in the firewall set
//   - lingering: in the firewall set but no longer tracked (ban outlived window)
//   - watching:  tracked but still under the ban threshold
func diffStatus(snap control.Snapshot) (anomalies, lingering, watching []string) {
	banned := map[string]bool{}
	for _, b := range snap.Bans {
		banned[b.IP] = true
	}
	tracked := map[string]bool{}
	for _, o := range snap.Offenders {
		tracked[o.IP] = true
		switch {
		case o.WouldBanSeconds > 0 && !banned[o.IP]:
			anomalies = append(anomalies, o.IP)
		case o.WouldBanSeconds == 0:
			watching = append(watching, o.IP)
		}
	}
	for _, b := range snap.Bans {
		if !tracked[b.IP] {
			lingering = append(lingering, b.IP)
		}
	}
	sort.Strings(anomalies)
	sort.Strings(lingering)
	sort.Strings(watching)
	return anomalies, lingering, watching
}

func sourceNote(live bool) string {
	if live {
		return "(live: daemon)"
	}
	return "(fallback: firewall set; daemon not running)"
}

func sortedBans(in []control.Ban) []control.Ban {
	out := append([]control.Ban(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func sortedOffenders(in []control.Offender) []control.Offender {
	out := append([]control.Offender(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func humanSeconds(s int64) string {
	if s <= 0 {
		return "-"
	}
	return (time.Duration(s) * time.Second).String()
}

func joinOrNone(xs []string) string {
	if len(xs) == 0 {
		return "none"
	}
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}
