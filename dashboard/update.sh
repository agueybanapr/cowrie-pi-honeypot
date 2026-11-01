#!/usr/bin/env bash
# Pull logs from the Pi and load them into the dashboard database.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
set -a; . ./.env; set +a
python3 -I pull_logs.py
docker compose run --rm --quiet-pull ingest
