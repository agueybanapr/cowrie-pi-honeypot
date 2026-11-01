#!/usr/bin/env bash
# Download the free DB-IP City Lite database (CC BY 4.0). Run about once a month.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/data/geoip"
curl -fsS --max-time 600 -o new.mmdb.gz "https://download.db-ip.com/free/dbip-city-lite-$(date +%Y-%m).mmdb.gz"
gunzip -f new.mmdb.gz
chmod 644 new.mmdb
mv -f new.mmdb dbip-city-lite.mmdb
ls -l dbip-city-lite.mmdb
