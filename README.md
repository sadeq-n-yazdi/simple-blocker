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
- **Pluggable firewall backends** — `ipset`+`iptables` (with `DOCKER-USER`
  support) or native `nftables`, auto-detected.
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

### Build manually

```sh
make build          # -> dist/simple-blocker
make test           # run the test suite
sudo ./dist/simple-blocker -config /etc/simple-blocker/config.yaml
```

## Configuration

YAML and JSON are interchangeable — pick by file extension. See
[`config.example.yaml`](config.example.yaml) and
[`config.example.json`](config.example.json).

```yaml
ipset_name: simple_blacklist   # name of the ipset / nft set
window: 3h                     # sliding window for counting offenses

firewall:
  backend: auto                # auto | iptables | nftables
  chains: [INPUT, DOCKER-USER] # iptables chains (ignored by nftables)

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

Durations use Go syntax (`10m`, `3h`, `24h`). Every source `pattern` must
contain a capturing group for the address — name it `(?P<ip>...)`; an unnamed
first group is accepted as a fallback.

### Adding a source

Append another entry under `sources`. For example, to ban IPs probing for
`.php`/`.env` files in an nginx container:

```yaml
  - type: docker
    name: nginx
    target: my-nginx-1
    pattern: '(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s.*?"[A-Z]+\s+\S*\.(?:php|env|xml)\S*\s+HTTP/\d\.\d".*\s404\s'
```

## Operating

```sh
systemctl status simple-blocker        # service health
journalctl -u simple-blocker -f        # live logs (bans are logged here)

# Inspect current bans:
sudo ipset list simple_blacklist       # iptables backend
sudo nft list set inet simple_blocker simple_blacklist   # nftables backend
```

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
- One firewall backend: `ipset` + `iptables`, or `nftables`
- `docker` CLI (only if using `docker` sources)

## License

MIT
