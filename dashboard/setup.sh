#!/usr/bin/env bash
# First-time setup: creates .env with random passwords if missing, then starts the stack.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
if [ ! -f .env ]; then
  umask 077
  { echo "DB_PASSWORD=$(openssl rand -hex 24)"
    echo "GRAFANA_DB_PASSWORD=$(openssl rand -hex 24)"
    echo "GRAFANA_ADMIN_PASSWORD=$(openssl rand -hex 16)"
    echo "COWRIE_LOG_TZ=${COWRIE_LOG_TZ:-America/New_York}"
    echo "PI_HOST=${PI_HOST:-<pi-ip>}"
    echo "PI_USER=${PI_USER:-<admin-user>}"
    echo "PI_PORT=22222"; } > .env
  echo "Created .env; check PI_HOST and PI_USER in it."
fi
# Containers run as other users, so mounted files must be world-readable (.env stays private).
mkdir -p data/logs data/geoip data/samples
chmod -R a+rX db grafana ingest data
[ -f data/geoip/dbip-city-lite.mmdb ] || ./fetch-geoip.sh
docker compose up -d --wait db grafana
docker compose build ingest
