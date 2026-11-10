#!/usr/bin/env bash
# Download the free DB-IP City Lite database (CC BY 4.0). Run about once a month.
# DB-IP publishes no checksums, so the download is checked to be a complete gzip file
# holding a MaxMind-format database before it replaces the current one.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/data/geoip"
umask 077
tmp="$(mktemp -d .new.XXXXXX)"
trap 'rm -rf "$tmp"' EXIT
curl -fsS --proto '=https' --max-time 600 --max-filesize 400000000 -o "$tmp/db.mmdb.gz" \
  "https://download.db-ip.com/free/dbip-city-lite-$(date +%Y-%m).mmdb.gz"
gzip -t "$tmp/db.mmdb.gz" || { echo "download is not a complete gzip file; keeping the old database" >&2; exit 1; }
gunzip "$tmp/db.mmdb.gz"
# Every MaxMind DB file has this marker near its end, before the metadata.
tail -c 131072 "$tmp/db.mmdb" | LC_ALL=C grep -aq $'\xab\xcd\xefMaxMind.com' \
  || { echo "download is not a MaxMind-format database; keeping the old database" >&2; exit 1; }
chmod 600 "$tmp/db.mmdb"
mv -f "$tmp/db.mmdb" dbip-city-lite.mmdb
ls -l dbip-city-lite.mmdb
