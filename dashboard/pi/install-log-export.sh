#!/usr/bin/env bash
# Run once on the Pi: sudo bash install-log-export.sh <admin-user>
# Lets <admin-user> run exactly one command as cowrie, without a password.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
user="${1:?usage: sudo bash install-log-export.sh <admin-user>}"
id "$user" >/dev/null
cd "$(dirname "$(readlink -f "$0")")"
install -m 755 cowrie-log-export /usr/local/bin/cowrie-log-export
rule="$(mktemp)"
printf '%s ALL=(cowrie) NOPASSWD: /usr/local/bin/cowrie-log-export ""\n' "$user" > "$rule"
visudo -cf "$rule" >/dev/null
install -m 440 "$rule" /etc/sudoers.d/cowrie-log-export
rm -f "$rule"
echo "Installed /usr/local/bin/cowrie-log-export and /etc/sudoers.d/cowrie-log-export"
