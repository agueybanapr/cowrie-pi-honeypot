#!/usr/bin/env bash
# First-time setup: creates .env with random passwords if missing, then starts the stack.
# Safe to re-run: an existing .env is kept, and settings added since are appended.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
if [ ! -f .env ]; then
  umask 077
  { echo "DB_PASSWORD=$(openssl rand -hex 24)"
    echo "GRAFANA_DB_PASSWORD=$(openssl rand -hex 24)"
    echo "GRAFANA_ADMIN_PASSWORD=$(openssl rand -hex 16)"
    echo "COWRIE_LOG_TZ=${COWRIE_LOG_TZ:-America/New_York}"
    echo "PI_HOST=${PI_HOST:-<pi-ip>}"
    echo "PI_USER=${PI_USER:-logpull}"
    echo "PI_PORT=22222"; } > .env
  echo "Created .env; check PI_HOST and PI_USER in it."
fi
# The ingest container runs as you, so it can read data/ without making it world-readable.
grep -q '^HOST_UID=' .env || echo "HOST_UID=$(id -u)" >> .env
grep -q '^HOST_GID=' .env || echo "HOST_GID=$(id -g)" >> .env
# Code and config are read by containers running as other users, so they must be world-readable.
# Captured data (logs, credentials, attacker scripts) stays private to you.
chmod -R a+rX db grafana ingest
mkdir -p data/logs data/geoip data/samples
chmod 700 data data/logs data/geoip data/samples
find data -type f -exec chmod 600 {} +
[ -f data/geoip/dbip-city-lite.mmdb ] || ./fetch-geoip.sh
docker compose up -d --wait db grafana
docker compose build ingest
