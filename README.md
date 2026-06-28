# simple-blocker

A small, dependency-light daemon that watches your logs for malicious probes
and brute-force attempts, then bans the offending IPs at the firewall with
escalating, time-limited bans.

It tails log sources (the systemd journal, Docker container logs), matches each
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
- **Pluggable log sources** — `journal` (systemd) and `docker` today; each is a
  regex with a named `(?P<ip>...)` capture group, so adding a new log shape is a
  config edit, not a code change.
- **Escalating bans** — more offenses inside the window ⇒ longer bans.
- **Sliding window** — old offenses age out automatically.
- **Restart-safe** — rules and sets are created idempotently; existing bans
  survive a restart.

## How it works

```
log source ──▶ regex (?P<ip>…) ──▶ offense tracker ──▶ ban schedule ──▶ firewall
 (journal,        per line          sliding window      offenses→time     ipset/iptables
  docker)                                                                  or nftables
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

firewall:
  mode: internal               # internal (pure-Go nftables) | external
  backend: auto                # external only: auto | iptables | nftables
  chains: [INPUT, DOCKER-USER] # external+iptables only

ban_schedule:                  # highest matching tier wins
  - { offenses: 2, ban: 10m }
  - { offenses: 3, ban: 30m }
  - { offenses: 5, ban: 1h }
  - { offenses: 7, ban: 24h }

sources:
  - type: journal              # journal | docker
    name: ssh                  # label shown in logs
    target: ssh                # systemd unit (journal) or container (docker)
    since: -1d                 # journal lookback
    pattern: 'Invalid user \S+ from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
```

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

### Source mode: internal vs external

Each source has a `mode`:

- **docker** — `internal` (default) reads container logs straight from the
  **Docker Engine API over the unix socket** (`/var/run/docker.sock`, override
  with `docker_host`) using only the Go standard library — no `docker` CLI
  needed. `external` shells out to `docker logs -f`.
- **journal** — always `external` (`journalctl`); `internal` is rejected.

Override docker sources at runtime with `-docker-mode internal|external`.

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

It bans nothing and needs no privileges — a pure diagnostic.

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
sudo nft delete table inet simple_blocker  # nftables backend
```

## Project layout

```
cmd/simple-blocker/    entrypoint (flags, wiring, signal handling)
internal/config/       YAML/JSON loading, defaults, validation
internal/blocker/      offense tracker (sliding window) + ban engine
internal/firewall/     Firewall interface + iptables and nftables backends
internal/source/       Source interface + journal and docker tailers
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
