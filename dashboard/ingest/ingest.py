"""Load Cowrie JSON logs into Postgres. Safe to re-run: events are keyed by a
hash of the raw line, and unchanged files are skipped. Log content is untrusted."""
import hashlib, json, os, re, sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import maxminddb
import psycopg

LOG_DIR = Path("/logs")
SAMPLE_DIR = Path("/samples")
GEOIP = Path("/geoip/dbip-city-lite.mmdb")
# Cowrie follows the Pi's timezone but still appends "Z", so stamps are local time.
LOG_TZ = ZoneInfo(os.environ.get("COWRIE_LOG_TZ", "America/New_York"))
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
MAX_TEXT = 16384
MAX_LINE = 1 << 20   # longer log lines are skipped, so one huge line can't exhaust memory
SQL = """INSERT INTO events (id, ts, eventid, session, src_ip, dst_port, protocol, sensor,
  username, password, input, url, shasum, filename, client_version, duration_s)
  VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO NOTHING"""


def text(value):
    if value is None:
        return None
    return CONTROL.sub("?", str(value))[:MAX_TEXT]


def number(value, kind=float):
    try:
        return kind(value)
    except (TypeError, ValueError):
        return None


def parse(raw):
    event = json.loads(raw)
    if not isinstance(event, dict) or not isinstance(event.get("eventid"), str):
        raise ValueError("not a Cowrie event")
    stamp = datetime.fromisoformat(str(event["timestamp"]).rstrip("Z"))
    duration = number(event.get("duration_ms"))
    duration = duration / 1000 if duration is not None else number(event.get("duration"))
    return (
        hashlib.sha256(raw).hexdigest(), stamp.replace(tzinfo=LOG_TZ), text(event["eventid"]),
        text(event.get("session")), text(event.get("src_ip")), number(event.get("dst_port"), int),
        text(event.get("protocol")), text(event.get("sensor")), text(event.get("username")),
        text(event.get("password")), text(event.get("input")), text(event.get("url")),
        text(event.get("shasum")), text(event.get("filename")), text(event.get("version")), duration,
    )


def locate(reader, ip):
    try:
        found = reader.get(ip) if reader else None
    except ValueError:
        found = None
    if not found:
        return (ip, None, None, None, None, None)
    country, location = found.get("country", {}), found.get("location", {})
    return (ip, country.get("iso_code"), country.get("names", {}).get("en"),
            found.get("city", {}).get("names", {}).get("en"),
            location.get("latitude"), location.get("longitude"))


def load_samples(cur):
    """Store verified text samples for display. Control characters become '?'."""
    cur.execute("""CREATE TABLE IF NOT EXISTS samples (
        sha256 text PRIMARY KEY, bytes integer NOT NULL, content text NOT NULL)""")
    cur.execute("GRANT SELECT ON samples TO grafana_ro")
    added = 0
    if not SAMPLE_DIR.is_dir():
        return added
    for path in SAMPLE_DIR.iterdir():
        if not re.fullmatch(r"[0-9a-f]{64}", path.name):
            continue
        data = path.read_bytes()
        content = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "?", data.decode("utf-8", "replace"))
        cur.execute("INSERT INTO samples VALUES (%s,%s,%s) ON CONFLICT (sha256) DO NOTHING",
                    (path.name, len(data), content))
        added += cur.rowcount
    return added


def main():
    dsn = f"host=db dbname=honeypot user=honeypot password={os.environ['DB_PASSWORD']}"
    added = bad = 0
    with psycopg.connect(dsn) as db, db.cursor() as cur:
        for path in sorted(LOG_DIR.glob("cowrie.json*")):
            info = path.stat()
            cur.execute("SELECT size, mtime FROM ingest_files WHERE name = %s", (path.name,))
            if cur.fetchone() == (info.st_size, info.st_mtime):
                continue
            with path.open("rb") as log:
                rows = []
                while raw := log.readline(MAX_LINE + 1):
                    if len(raw) > MAX_LINE:
                        bad += 1
                        while raw and not raw.endswith(b"\n"):   # skip the rest of that line
                            raw = log.readline(MAX_LINE)
                        continue
                    try:
                        rows.append(parse(raw.rstrip(b"\r\n")))
                    except (ValueError, TypeError, KeyError):
                        bad += 1
                    if len(rows) >= 1000:
                        cur.executemany(SQL, rows, returning=False)
                        added += len(rows)
                        rows = []
                if rows:
                    cur.executemany(SQL, rows, returning=False)
                    added += len(rows)
            cur.execute("""INSERT INTO ingest_files VALUES (%s,%s,%s) ON CONFLICT (name)
                           DO UPDATE SET size = EXCLUDED.size, mtime = EXCLUDED.mtime""",
                        (path.name, info.st_size, info.st_mtime))
        cur.execute("""SELECT DISTINCT src_ip FROM events e WHERE src_ip IS NOT NULL
                       AND NOT EXISTS (SELECT 1 FROM ip_geo g WHERE g.ip = e.src_ip)""")
        ips = [row[0] for row in cur.fetchall()]
        reader = maxminddb.open_database(str(GEOIP)) if GEOIP.exists() else None
        if ips:
            cur.executemany("INSERT INTO ip_geo VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                            [locate(reader, ip) for ip in ips])
        new_samples = load_samples(cur)
        cur.execute("SELECT count(*) FROM events")
        total = cur.fetchone()[0]
    print(f"processed {added} lines, skipped {bad} malformed, {len(ips)} new IPs, {new_samples} new samples, {total} events in database"
          + ("" if reader else " (no GeoIP database)"))


if __name__ == "__main__":
    sys.exit(main())
