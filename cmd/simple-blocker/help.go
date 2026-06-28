package main

import (
	"fmt"
	"io"
	"os"
)

// This file centralizes all CLI help so the top-level overview, the
// `help <command>` topics, and each subcommand's `-h`/`--help` output stay
// consistent. Help text for an explicit help request goes to stdout and exits
// 0; usage shown alongside an error goes to stderr.

// printMainHelp writes the top-level overview: synopsis, command list, daemon
// flags, and examples.
func printMainHelp(w io.Writer) {
	fmt.Fprint(w, `simple-blocker — watch log sources for malicious probes and ban offending IPs
through the host firewall (ipset+iptables, nftables, or native netlink).

USAGE:
    simple-blocker [daemon-flags]        run the daemon (the default when no command is given)
    simple-blocker <command> [args]      run a management command

COMMANDS:
    status               show currently-banned IPs and, when the daemon is up, the offense tracker
    check                dry-run: scan logs and print what would be banned (bans nothing)
    whitelist            manage the never-ban list (add | remove | show)
    blacklist            manage the always-ban list (add | remove | show)
    version              print version, commit, build date, and Go version
    help [command]       show this overview, or detailed help for a command

DAEMON FLAGS (used when no command is given):
    -config path         config file: .yaml, .yml or .json (default /etc/simple-blocker/config.yaml)
    -firewall-mode mode  override firewall.mode: internal or external
    -docker-mode mode    override the mode for all docker sources: internal or external
    -control-socket path override the control_socket path
    -version             print version information and exit
    -h, --help           show this help

CONFIGURATION:
    Most behavior — log sources, ban schedule, firewall mode/backend, whitelist,
    blacklist, and IPv6 enforcement (enforce_ipv6) — is set in the config file,
    not via flags. See the bundled config.example.yaml / config.example.json for
    a fully-commented template. Lists can also be edited live with the
    whitelist/blacklist commands; the daemon hot-reloads them within seconds.

EXAMPLES:
    simple-blocker                                   # run the daemon with the default config
    simple-blocker -config /etc/simple-blocker/config.yaml
    simple-blocker status                            # what is banned right now
    simple-blocker check -source ssh                 # dry-run only the "ssh" source
    sudo simple-blocker blacklist add 198.51.100.7   # ban an address permanently
    sudo simple-blocker whitelist add 203.0.113.4    # never ban it (and lift any live ban)

Run "simple-blocker help <command>" for detailed help on a command.
`)
}

// commandHelp returns the detailed help text for a single command, and whether
// the topic is known.
func commandHelp(topic string) (string, bool) {
	switch topic {
	case "status":
		return statusHelp, true
	case "check":
		return checkHelp, true
	case "whitelist":
		return listHelp("whitelist"), true
	case "blacklist":
		return listHelp("blacklist"), true
	case "version":
		return versionHelp, true
	}
	return "", false
}

// runHelp handles `help [topic]`, `-h`, and `--help` at the top level. It
// returns the process exit code: 0 for a resolved topic, 2 for an unknown one.
func runHelp(topic string) int {
	if topic == "" || topic == "help" {
		printMainHelp(os.Stdout)
		return 0
	}
	text, ok := commandHelp(topic)
	if !ok {
		fmt.Fprintf(os.Stderr, "simple-blocker: no help topic for %q\n\n", topic)
		printMainHelp(os.Stderr)
		return 2
	}
	fmt.Fprint(os.Stdout, text)
	return 0
}

const statusHelp = `simple-blocker status — show banned IPs and the offense tracker

USAGE:
    simple-blocker status [flags]

DESCRIPTION:
    Prints the IPs currently held in the firewall ban set. When the daemon is
    running, status connects to its control socket and additionally shows the
    offense tracker and a diff highlighting the noteworthy cases:
      - over threshold but NOT banned (an anomaly worth investigating),
      - banned but no longer tracked (a ban that outlived the window/restart),
      - tracked but still under the threshold (being watched).
    When the daemon is not running, status falls back to reading the firewall
    set directly — this needs root, and the tracker view is unavailable.

FLAGS:
    -config path          path to the config file (default /etc/simple-blocker/config.yaml)
    -control-socket path  control socket path (overrides config)
    -json                 emit the raw snapshot as JSON instead of a table
    -h, --help            show this help

EXAMPLES:
    simple-blocker status
    sudo simple-blocker status            # read the firewall set when the daemon is down
    simple-blocker status -json
`

const checkHelp = `simple-blocker check — dry-run a log scan and print what would be banned

USAGE:
    simple-blocker check [flags]

DESCRIPTION:
    Scans the configured log sources and prints every line that matches a
    source pattern, with the captured IP highlighted, followed by the action
    the daemon would take — whitelisted, blacklisted (permanent), or the
    escalating ban schedule — simulated against an in-memory dry-run tracker.
    Nothing is ever banned. A pure-IPv6 target reports "would not ban" unless
    enforce_ipv6 is enabled in the config, mirroring the daemon exactly.

FLAGS:
    -config path   path to the config file (default /etc/simple-blocker/config.yaml)
    -follow        stream logs live instead of reading recent history
    -source name   only check the named source (default: all sources)
    -color mode    colorize the captured IP: auto | always | never (default auto)
    -actions       print the action for each match (default true; use -actions=false to hide)
    -h, --help     show this help

EXAMPLES:
    simple-blocker check
    simple-blocker check -source ssh -follow
    simple-blocker check -color never -actions=false
`

const versionHelp = `simple-blocker version — print build information

USAGE:
    simple-blocker version
    simple-blocker -version

DESCRIPTION:
    Prints the version, commit, build date, and Go toolchain version. The
    version and commit are stamped at build time; when built without ldflags
    they fall back to the Go module's embedded VCS stamp.
`

// listHelp renders the detailed help for whitelist/blacklist, which share a
// shape. other is the complementary list, used to explain precedence.
func listHelp(list string) string {
	other := "blacklist"
	thisLine := "whitelist — addresses the daemon never bans, even if they trip a monitored pattern."
	otherLine := "blacklist — addresses banned permanently the moment they trip a pattern."
	if list == "blacklist" {
		other = "whitelist"
		thisLine = "blacklist — addresses banned permanently the moment they trip a monitored pattern."
		otherLine = "whitelist — addresses the daemon never bans, even if they trip a pattern."
	}
	return fmt.Sprintf(`simple-blocker %[1]s — manage the %[1]s

USAGE:
    simple-blocker %[1]s show [flags]
    simple-blocker %[1]s add    <ip|range|cidr> [flags]
    simple-blocker %[1]s remove <ip|range|cidr> [flags]

DESCRIPTION:
    %[2]s
    %[3]s
    Whitelist always wins over blacklist. Each entry is a single IPv4 or IPv6
    address, an inclusive range "FROM-TO", or a CIDR block.

    Edits are written to the config file, preserving YAML comments / JSON keys.
    A running daemon applies them within a few seconds via its file watcher —
    no restart needed. On "remove" (and on "whitelist add") any matching live
    bans are lifted from the firewall set immediately; that step needs root
    (and is skipped with a note if the firewall can't be reached).

ACTIONS:
    show               print the current %[1]s entries
    add <spec>         add an address/range/CIDR to the %[1]s
    remove <spec>      remove a previously-added entry from the %[1]s

FLAGS:
    -config path       path to the config file (default /etc/simple-blocker/config.yaml)
    -h, --help         show this help

EXAMPLES:
    simple-blocker %[1]s show
    sudo simple-blocker %[1]s add 198.51.100.0/24
    sudo simple-blocker %[1]s remove 198.51.100.7

NOTE:
    The complementary list is "%[4]s"; see "simple-blocker help %[4]s".
`, list, thisLine, otherLine, other)
}
