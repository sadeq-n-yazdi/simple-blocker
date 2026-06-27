#!/usr/bin/env bash
#
# simple-blocker installer.
#
# Builds the binary, installs the dependencies it needs (a firewall backend),
# drops a config under /etc/simple-blocker, and installs + enables the systemd
# service. Safe to re-run: every step is idempotent.
#
# Usage:
#   sudo ./scripts/install.sh [--backend auto|iptables|nftables] [--no-enable]
#
set -euo pipefail

# ---- settings -------------------------------------------------------------
PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="$PREFIX/bin"
CONFIG_DIR="/etc/simple-blocker"
SERVICE_NAME="simple-blocker.service"
SERVICE_DIR="/etc/systemd/system"
BACKEND="auto"
ENABLE_SERVICE=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---- pretty logging -------------------------------------------------------
log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# ---- args -----------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --backend)    BACKEND="${2:?--backend needs a value}"; shift 2 ;;
    --no-enable)  ENABLE_SERVICE=0; shift ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//;1d' | sed '/^!/d'
      exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "please run as root (sudo $0)"
command -v systemctl >/dev/null 2>&1 || die "systemd (systemctl) is required but not found"

# ---- detect package manager ----------------------------------------------
PKG=""
for candidate in apt-get dnf yum pacman zypper apk; do
  if command -v "$candidate" >/dev/null 2>&1; then PKG="$candidate"; break; fi
done

pkg_install() {
  # pkg_install <pkg...>
  [[ -n "$PKG" ]] || die "no supported package manager found; install $* manually"
  log "Installing packages with $PKG: $*"
  case "$PKG" in
    apt-get) apt-get update -qq && apt-get install -y "$@" ;;
    dnf|yum) "$PKG" install -y "$@" ;;
    pacman)  pacman -Sy --noconfirm "$@" ;;
    zypper)  zypper --non-interactive install "$@" ;;
    apk)     apk add --no-cache "$@" ;;
  esac
}

have() { command -v "$1" >/dev/null 2>&1; }

# ---- choose & ensure firewall backend ------------------------------------
ensure_iptables() {
  have iptables || pkg_install iptables
  have ipset    || pkg_install ipset
}
ensure_nftables() {
  have nft || pkg_install nftables
}

resolve_backend() {
  case "$BACKEND" in
    iptables) ensure_iptables; echo iptables ;;
    nftables) ensure_nftables; echo nftables ;;
    auto)
      if have iptables && have ipset; then
        echo iptables
      elif have nft; then
        echo nftables
      else
        # Nothing present: prefer nftables on modern systems, fall back to
        # installing the iptables stack if nftables is unavailable.
        if pkg_install nftables 2>/dev/null && have nft; then
          echo nftables
        else
          ensure_iptables
          echo iptables
        fi
      fi ;;
    *) die "invalid --backend: $BACKEND" ;;
  esac
}

log "Resolving firewall backend (requested: $BACKEND)"
RESOLVED_BACKEND="$(resolve_backend)"
log "Using firewall backend: $RESOLVED_BACKEND"

# ---- build the binary -----------------------------------------------------
have go || die "Go toolchain not found. Install Go (https://go.dev/dl/) and re-run."
log "Building simple-blocker"
( cd "$REPO_DIR" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$BIN_DIR/simple-blocker" ./cmd/simple-blocker )
log "Installed binary: $BIN_DIR/simple-blocker"

# ---- install config (never clobber an existing one) ----------------------
install -d -m 0755 "$CONFIG_DIR"
if [[ -f "$CONFIG_DIR/config.yaml" ]]; then
  warn "Config already exists at $CONFIG_DIR/config.yaml — leaving it untouched"
else
  install -m 0644 "$REPO_DIR/config.example.yaml" "$CONFIG_DIR/config.yaml"
  log "Installed default config: $CONFIG_DIR/config.yaml (edit it before relying on it)"
fi

# ---- install systemd service ---------------------------------------------
log "Installing systemd unit"
install -m 0644 "$REPO_DIR/$SERVICE_NAME" "$SERVICE_DIR/$SERVICE_NAME"
systemctl daemon-reload

if [[ "$ENABLE_SERVICE" -eq 1 ]]; then
  log "Enabling and starting $SERVICE_NAME"
  systemctl enable --now "$SERVICE_NAME"
  systemctl --no-pager status "$SERVICE_NAME" || true
else
  log "Service installed but not enabled (--no-enable). Start it with:"
  echo "    sudo systemctl enable --now $SERVICE_NAME"
fi

log "Done. View logs with: journalctl -u $SERVICE_NAME -f"
