#!/bin/sh
# Runs after the package is installed or upgraded.
set -e

# Seed a default config on first install only; never clobber a user's edits.
if [ ! -f /etc/simple-blocker/config.yaml ]; then
    if [ -f /etc/simple-blocker/config.example.yaml ]; then
        cp /etc/simple-blocker/config.example.yaml /etc/simple-blocker/config.yaml
    fi
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    # Enable so it starts on boot, but don't start it now: the admin should
    # review /etc/simple-blocker/config.yaml first.
    systemctl enable simple-blocker.service || true
    echo "simple-blocker installed. Edit /etc/simple-blocker/config.yaml, then:"
    echo "    sudo systemctl start simple-blocker"
fi

exit 0
