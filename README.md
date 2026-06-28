# simple-blocker

A small, dependency-light daemon that watches your logs for malicious probes
and brute-force attempts, then bans the offending IPs at the firewall with
escalating, time-limited bans.

It tails log sources (the systemd journal, Docker container logs, plain log
files), matches each
line against configurable regular expressions, and when an address crosses an
offense threshold within a sliding window it is dropped via **ipset + iptables**
or **nftables** — whichever your host has. Bans expire automatically.

This is a Go rewrite of an original Python prototype, restructured to be
configurable and extensible.

## Features

- **Config-driven** — YAML *or* JSON (chosen by file extension), no recompile.
- **Internal or external enforcement** — the firewall runs as **pure-Go
  nftables over netlink** (no external binaries) or shells out to the host's
  tools; pick per-deployment via `firewall.mode` or `-firewall-mode`.
- **Pluggable firewall backends** (external mode) — `ipset`+`iptables` (with
  `DOCKER-USER` support) or native `nftables`, auto-detected.
- **Pluggable log sources** — `journal` (systemd), `docker`, and `file` (tail a
  plain log file, rotation-aware) today; each is a regex with a named
  `(?P<ip>...)` capture group, so adding a new log shape is a config edit, not a
  code change.
- **Escalating bans** — more offenses inside the window ⇒ longer bans.
- **Whitelist & blacklist** — never-ban and permanent-ban lists of IPs, ranges,
  or CIDRs, managed live (`simple-blocker whitelist|blacklist add|remove|show`)
  and hot-reloaded from the config file without a restart.
- **Sliding window** — old offenses age out automatically.
- **Restart-safe** — rules and sets are created idempotently; existing bans
  survive a restart.

## How it works

```
log source ──▶ regex (?P<ip>…) ──▶ offense tracker ──▶ ban schedule ──▶ firewall
 (journal,        per line          sliding window      offenses→time     ipset/iptables
  docker, file)                                                            or nftables
```

## Install

Requires a Linux host with **systemd** and the **Go toolchain** (to build).
The installer fetches a firewall backend for you if one isn't present.

```sh
git clone https://code.sadeq.uk/simple-blocker.git   # or your fork
cd simple-blocker
sudo ./scripts/install.sh
```

The installer (idempotent — safe to re-run):

1. Checks for `systemd`; aborts if missing.
2. Resolves a firewall backend (`--backend auto|iptables|nftables`) and installs
   `ipset`+`iptables` or `nftables` via your package manager (`apt`, `dnf`,
   `yum`, `pacman`, `zypper`, or `apk`) if absent.
3. Builds the binary to `/usr/local/bin/simple-blocker`.
4. Installs a default config to `/etc/simple-blocker/config.yaml` (never
   overwrites an existing one).
5. Installs, enables, and starts the `simple-blocker.service` systemd unit.

Options:

```sh
sudo ./scripts/install.sh --backend nftables   # force a backend
sudo ./scripts/install.sh --no-enable          # install but don't start
```

After installing, **edit `/etc/simple-blocker/config.yaml`** for your hosts and
restart: `sudo systemctl restart simple-blocker`.

### From a prebuilt package (.deb / .rpm)

Each tagged release publishes static binaries and packages for Linux
**amd64**, **arm64**, and **armv7** on the
[releases page](https://github.com/sadeq-n-yazdi/simple-blocker/releases).

```sh
# Debian / Ubuntu (pick your arch)
curl -LO https://github.com/sadeq-n-yazdi/simple-blocker/releases/latest/download/simple-blocker_<version>_linux_amd64.deb
sudo apt install ./simple-blocker_<version>_linux_amd64.deb

# Fedora / RHEL / openSUSE
sudo rpm -i simple-blocker_<version>_linux_amd64.rpm
```

The package installs the binary to `/usr/bin`, the systemd unit, and example
configs under `/etc/simple-blocker`. On first install it seeds
`/etc/simple-blocker/config.yaml` and enables (but does not start) the service.
Edit the config, then `sudo systemctl start simple-blocker`.

### Build manually

```sh
make build          # -> dist/simple-blocker (embeds version + commit hash)
make test           # run the test suite
sudo ./dist/simple-blocker -config /etc/simple-blocker/config.yaml
```

Check the build metadata at any time:

```sh
simple-blocker version     # or: simple-blocker -version
# simple-blocker v0.1.0 (commit 1a2b3c4..., built 2026-06-28T..., go1.26.4)
```

Released binaries are stamped via linker flags; a plain `go build` still shows
the commit via Go's embedded VCS stamp.

## Configuration

YAML and JSON are interchangeable — pick by file extension. See
[`config.example.yaml`](config.example.yaml) and
[`config.example.json`](config.example.json).

```yaml
ipset_name: simple_blacklist   # name of the ipset / nft set
window: 3h                     # sliding window for counting offenses

whitelist:                     # never ban these (wins over blacklist)
  - 203.0.113.4                #   single IP (v4 or v6)
  - 10.0.0.0/24                #   CIDR block
  - 192.168.1.10-192.168.1.40  #   inclusive range FROM-TO
  - 2001:db8::/32              #   IPv6 CIDR
blacklist:                     # ban permanently the moment they trip a pattern
  - 198.51.100.0/24

firewall:
  mode: internal               # internal (pure-Go nftables) | external
  backend: auto                # external only: auto | iptables | nftables
  chains: [INPUT, DOCKER-USER] # external+iptables only
  enforce_ipv6: false          # opt in to banning IPv6 offenders (default off)

ban_schedule:                  # highest matching tier wins
  - { offenses: 2, ban: 10m }
  - { offenses: 3, ban: 30m }
  - { offenses: 5, ban: 1h }
  - { offenses: 7, ban: 24h }

sources:
  - type: journal              # journal | docker | file
    name: ssh                  # label shown in logs
    target: ssh                # systemd unit (journal), container (docker), or file path (file)
    since: -1d                 # journal/file lookback
    pattern: 'Invalid user \S+ from \[?(?P<ip>[0-9a-fA-F:.]+)\]?'

  - type: file                 # tail a plain log file (e.g. an nginx access log)
    name: nginx-file
    target: /var/log/nginx/access.log
    since: -1d                 # skip lines older than this (needs a ts group, below)
    # time_format: '02/Jan/2006:15:04:05 -0700'   # optional layout override
    pattern: '(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s.*\[(?P<ts>[^\]]+)\]\s"[A-Z]+\s+\S*\.(?:php|env)\S*\s+HTTP/\d\.\d".*\s404\s'
```

The `ssh` pattern above uses a **dual-stack** capture group: it matches IPv4,
bare IPv6, and bracketed IPv6 (`from [2001:db8::1]:443`). The captured token is
validated by the daemon, so anything that isn't a real address is ignored — a
permissive class like `[0-9a-fA-F:.]+` is safe. For IPv4 only, use
`(?P<ip>\d{1,3}(?:\.\d{1,3}){3})`.

### Firewall: internal vs external

`firewall.mode: internal` (the default) manages nftables directly over netlink
from within the process — no `nft`, `iptables`, or `ipset` binary required, just
a kernel with nftables. It creates an `inet simple_blocker` table with a timeout
set and an `ip saddr @set drop` rule.

`firewall.mode: external` shells out to the host's tools and honours `backend`
(`auto`/`iptables`/`nftables`) — use it on hosts without nftables, or when you
need iptables `DOCKER-USER` integration. Override the config at runtime with the
flag:

```sh
simple-blocker -firewall-mode external -config /etc/simple-blocker/config.yaml
```

Either way the process needs `CAP_NET_ADMIN` (run as root or via the systemd
unit). On shutdown the drop rule is removed but the ban set is kept, so active
bans survive a restart.

Durations use Go syntax (`10m`, `3h`, `24h`). Every source `pattern` must
contain a capturing group for the address — name it `(?P<ip>...)`; an unnamed
first group is accepted as a fallback.

### Whitelist & blacklist

Two optional lists give you manual control on top of the schedule:

- **`whitelist`** — addresses the daemon must **never** ban, even when they trip
  a pattern. Whitelist wins over blacklist.
- **`blacklist`** — addresses banned **permanently** the moment they trip a
  monitored pattern (reactive, not on every packet).

Each entry is a single IP (v4 or v6), an inclusive range `FROM-TO`, or a CIDR
block. IPv6 entries are always honored for **matching**: a v6 whitelist entry
fully protects, and a v6 blacklist/offender is **enforced** when
`firewall.enforce_ipv6` is on (see below). With enforcement off (the default), a
v6 ban target is logged and skipped.

### IPv6 enforcement

Matching is dual-stack out of the box, but actually **banning** IPv6 offenders is
opt-in via `firewall.enforce_ipv6: true`. When enabled, each backend maintains a
parallel IPv6 ban set and drop rule next to the IPv4 ones:

- **internal / nftables** — an `ipv6_addr` set with an `ip6 saddr @set6 drop`
  rule in the same `inet` table.
- **iptables** — a second `hash:ip family inet6` ipset referenced from
  `ip6tables` in the configured chains.

It is **best-effort and failure-tolerant**: if a host can't install v6 rules
(e.g. `ip6tables` or a `DOCKER-USER` v6 chain is absent on a Docker host without
IPv6), the daemon logs the skip and keeps enforcing IPv4 — it never fails to
start. For this to do anything, your source `pattern`s must capture IPv6 (the
`ssh` example above does). It's off by default so upgrading an existing host
doesn't silently start touching `ip6tables`.

Manage the lists live without editing files by hand or restarting the daemon:

```sh
sudo simple-blocker blacklist add 198.51.100.0/24   # add a CIDR
sudo simple-blocker whitelist add 203.0.113.4        # never ban this host
sudo simple-blocker blacklist remove 198.51.100.7    # also lifts any live ban
simple-blocker whitelist show                        # list current entries
```

These edit the config file in place (preserving YAML comments) and the daemon
applies the change within a couple of seconds — it watches the config file and
hot-reloads the lists with no restart. `remove` (and `whitelist add`) also delete
matching entries from the live firewall set, so the change takes effect
immediately; that part needs root. Only the lists are hot-reloaded — changing
sources, the firewall backend, or the schedule still requires a restart.

### Source mode: internal vs external

Each source has a `mode`:

- **docker** — `internal` (default) reads container logs straight from the
  **Docker Engine API over the unix socket** (`/var/run/docker.sock`, override
  with `docker_host`) using only the Go standard library — no `docker` CLI
  needed. `external` shells out to `docker logs -f`.
- **journal** — always `external` (`journalctl`); `internal` is rejected.
- **file** — has no mode (setting one is an error).

Override docker sources at runtime with `-docker-mode internal|external`.

### File sources and the time window

A `file` source tails a plain log file. It reads from the **start**, follows it
live, and survives **log rotation** — both rename + recreate (e.g. logrotate's
default) and `copytruncate`. The file not existing yet is fine; it's retried
until it appears.

Because it reads from the start, a restart would re-count old lines. To avoid
that, give the pattern an optional **`(?P<ts>...)`** capture for the line's
timestamp: lines older than `since` (default `-1d`) are skipped. The format is
**auto-detected** from common layouts (nginx/Apache, ISO 8601/RFC 3339, syslog);
set `time_format` (a Go reference layout) to override. Two caveats:

- **Fail-closed:** when a `ts` group is configured, a line whose timestamp can't
  be parsed is **skipped**. Verify your pattern with `simple-blocker check`
  before relying on it — a format mismatch silently disables that source.
- **No `ts` group** means no time filtering: the whole file is read on every
  start (and a restart re-counts old offenses).

Even with a `ts` group, a restart replays up to `since` of history (matching the
`journal` source's `-1d` default). On a busy web access log that can be a large
backlog, and each replayed hit is counted as happening *now* — so a restart can
re-ban IPs whose probing is up to `since` old. Shorten `since` if that matters.

### Adding a source

Append another entry under `sources`. For example, to ban IPs probing for
`.php`/`.env` files in an nginx container (internal docker mode, the default):

```yaml
  - type: docker
    name: nginx
    target: my-nginx-1
    mode: internal   # or external to use the docker CLI
    pattern: '(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s.*?"[A-Z]+\s+\S*\.(?:php|env|xml)\S*\s+HTTP/\d\.\d".*\s404\s'
```

## Operating

```sh
systemctl status simple-blocker        # service health
journalctl -u simple-blocker -f        # live logs (bans are logged here)
```

### `status` — see what's blocked

```sh
sudo simple-blocker status             # human table
sudo simple-blocker status -json       # machine-readable
```

`status` shows the **currently-banned IPs** (with remaining time) and, when the
daemon is running, its **offense tracker** plus the **diff** between them — most
usefully any IP that is over the ban threshold but somehow *not* in the firewall
set. It reads the daemon's read-only control socket
(`control_socket`, default `/run/simple-blocker.sock`); if the daemon isn't
running it falls back to reading the firewall set directly (needs root) and says
so. You can still inspect the raw set yourself:

```sh
sudo ipset list simple_blacklist                          # iptables backend
sudo nft list set inet simple_blocker simple_blacklist    # nftables backend
```

With `enforce_ipv6` on, IPv6 bans live in a parallel set whose name is the IPv4
set name with `6` appended (e.g. `simple_blacklist6`); `status` merges both:

```sh
sudo ipset list simple_blacklist6                         # iptables backend (v6)
sudo nft list set inet simple_blocker simple_blacklist6   # nftables backend (v6)
```

### `check` — dry-run the log matching

```sh
simple-blocker check                       # scan recent logs, then exit
simple-blocker check -follow               # stream live until Ctrl-C
simple-blocker check -source nginx         # only one source
simple-blocker check -actions=false        # lines only, no action
simple-blocker check -color never          # disable IP highlighting
```

`check` reads each configured source, prints every line that matches its
pattern with the **captured IP highlighted**, and — on by default — the
**action** the daemon would take, simulated against your real ban schedule
(escalating offense counts, no actual bans):

```
[nginx] 45.9.1.2 … "GET /wp-login.php HTTP/1.1" 404 …
    → offense #2 from 45.9.1.2 within 3h → would ban 10m
```

It bans nothing and needs no privileges — a pure diagnostic. Whitelisted and
blacklisted addresses are reflected here too ("would not ban" / "would ban
permanently").

### `whitelist` / `blacklist` — manage the lists

```sh
sudo simple-blocker blacklist add 198.51.100.0/24
sudo simple-blocker whitelist add 203.0.113.4
sudo simple-blocker blacklist remove 198.51.100.7   # also lifts a live ban
simple-blocker blacklist show
```

See [Whitelist & blacklist](#whitelist--blacklist) above for the entry grammar
and hot-reload behaviour.

On shutdown the service removes its drop rules but **keeps the ban set**, so
in-flight bans persist across restarts.

## Uninstall

```sh
sudo systemctl disable --now simple-blocker
sudo rm /etc/systemd/system/simple-blocker.service /usr/local/bin/simple-blocker
sudo rm -r /etc/simple-blocker
sudo systemctl daemon-reload
# Optionally drop the ban set:
sudo ipset destroy simple_blacklist        # iptables backend
sudo ipset destroy simple_blacklist6       # iptables backend (if enforce_ipv6 was on)
sudo nft delete table inet simple_blocker  # nftables backend (removes both families)
```

## Project layout

```
cmd/simple-blocker/    entrypoint (flags, wiring, signal handling)
internal/config/       YAML/JSON loading, defaults, validation
internal/blocker/      offense tracker (sliding window) + ban engine
internal/firewall/     Firewall interface + iptables and nftables backends
internal/source/       Source interface + journal, docker, and file tailers
scripts/install.sh     installer (deps, build, systemd)
```

Extension points are the `firewall.Firewall` and `source.Source` interfaces —
implement either to add a backend or a log source.

## Requirements

- Linux with systemd
- Go (build-time only; the binary is static, `CGO_ENABLED=0`)
- A firewall: a kernel with nftables (internal mode), or `ipset`+`iptables` / `nftables` tools (external mode)
- `docker` CLI only for `docker` sources in `external` mode (internal mode uses the API socket directly)

## License

MIT
