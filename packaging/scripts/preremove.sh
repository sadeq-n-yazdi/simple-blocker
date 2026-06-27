#!/bin/sh
# Runs before the package is removed.
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop simple-blocker.service || true
    systemctl disable simple-blocker.service || true
fi

exit 0
