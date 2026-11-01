#!/usr/bin/env bash
# One-time installer for the daily Cowrie ntfy report. Run with: sudo bash install-cowrie-report.sh
# Asks for an ntfy.sh topic (or generates one). Safe to re-run: scripts and units are
# replaced; an existing /etc/cowrie-report.env is kept unless you choose a new topic.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
cd "$(dirname "$(readlink -f "$0")")"
for f in cowrie-stats cowrie-report; do
  [ -f "$f" ] || { echo "Missing $f next to this installer." >&2; exit 1; }
done
command -v curl >/dev/null || { echo "curl is not installed: sudo apt install -y curl" >&2; exit 1; }

echo "Installing /usr/local/bin/cowrie-stats and /usr/local/bin/cowrie-report"
install -m 755 cowrie-stats /usr/local/bin/cowrie-stats
install -m 755 cowrie-report /usr/local/bin/cowrie-report

ENV=/etc/cowrie-report.env

# Ask for an ntfy.sh topic, or generate a random one when left blank.
choose_topic() {
  local t ans
  echo
  echo "ntfy.sh topics are public: anyone who knows the name can read the reports."
  echo "Use a long, random-looking name, or leave blank to generate one."
  while true; do
    read -rp "ntfy.sh topic (blank = generate): " t
    if [ -z "$t" ]; then
      t="cowrie-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
      echo "Generated topic: $t"
      break
    fi
    if ! [[ "$t" =~ ^[A-Za-z0-9_-]{1,64}$ ]]; then
      echo "Topics may only use letters, digits, '-' and '_' (max 64 characters)."
      continue
    fi
    if [ "${#t}" -lt 16 ]; then
      read -rp "'$t' is short and easy to guess. Use it anyway? [y/N] " ans
      [[ "$ans" =~ ^[Yy]$ ]] || continue
    fi
    break
  done
  topic="$t"
}

if [ -f "$ENV" ]; then
  current="$(sed -n 's/^NTFY_URL=//p' "$ENV")"
  echo "Current report destination: ${current:-<none>}"
  read -rp "Keep it? [Y/n] " keep
  if [[ "$keep" =~ ^[Nn]$ ]]; then
    choose_topic
    cp -p "$ENV" "$ENV.bak.$(date +%Y%m%d%H%M%S)"
    sed -i "s|^NTFY_URL=.*|NTFY_URL=https://ntfy.sh/$topic|" "$ENV"
    echo "Updated $ENV (previous version backed up next to it)"
  else
    echo "Keeping existing $ENV"
  fi
else
  choose_topic
  umask 077
  cat > "$ENV" <<EOF
# Settings for the daily Cowrie report (read by cowrie-report.service).
# Anyone who knows a public ntfy.sh topic name can read it, so keep it secret.
NTFY_URL=https://ntfy.sh/$topic
#NTFY_TOKEN=
REPORT_HOURS=24
REPORT_TOP=5
EOF
  chmod 600 "$ENV"
  echo "Created $ENV"
fi

echo "Writing systemd units"
cat > /etc/systemd/system/cowrie-report.service <<'EOF'
[Unit]
Description=Send Cowrie activity report via ntfy
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=cowrie
Group=cowrie
EnvironmentFile=/etc/cowrie-report.env
ExecStart=/usr/local/bin/cowrie-report
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
EOF

cat > /etc/systemd/system/cowrie-report.timer <<'EOF'
[Unit]
Description=Daily Cowrie activity report

[Timer]
OnCalendar=*-*-* 22:00:00
Persistent=true
RandomizedDelaySec=5min

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now cowrie-report.timer

echo
echo "Sending a test report now..."
if systemctl start cowrie-report.service; then
  echo "Test report sent."
else
  echo "Test report FAILED. See: journalctl -u cowrie-report -n 30" >&2
fi

echo
grep '^NTFY_URL=' "$ENV" | sed 's/^NTFY_URL=/Subscribe to this topic in the ntfy app: /'
systemctl list-timers cowrie-report.timer --no-pager | head -n 2
