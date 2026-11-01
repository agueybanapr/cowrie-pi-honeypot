#!/usr/bin/env python3
"""Generate the Grafana dashboards in grafana/dashboards/. Run after editing."""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "dashboards"
DS = {"type": "grafana-postgresql-datasource", "uid": "honeypot-pg"}
SESSION_URL = "/d/honeypot-session/session?var-session=${__value.raw}&from=now-90d&to=now"
_next = [0]


def panel(kind, title, sql, x, y, w, h, fmt="table", desc="", **extra):
    _next[0] += 1
    item = {"id": _next[0], "type": kind, "title": title, "description": desc, "datasource": DS,
            "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "targets": [{"refId": "A", "datasource": DS, "rawQuery": True, "rawSql": sql, "format": fmt, "editorMode": "code"}],
            "fieldConfig": {"defaults": {}, "overrides": []}, "options": {}}
    item.update(extra)
    return item


def stat(title, sql, x, w=4):
    p = panel("stat", title, sql, x, 0, w, 4)
    p["options"] = {"reduceOptions": {"calcs": ["lastNotNull"]}, "colorMode": "value", "graphMode": "none"}
    p["fieldConfig"]["defaults"] = {"noValue": "0", "thresholds": {"mode": "absolute", "steps": [{"color": "blue", "value": None}]}}
    return p


def series(title, sql, x, y, w, h=8, style="line"):
    p = panel("timeseries", title, sql, x, y, w, h, fmt="time_series")
    p["fieldConfig"]["defaults"] = {"custom": {"drawStyle": style, "fillOpacity": 25, "stacking": {"mode": "normal"}, "spanNulls": False}}
    return p


def table(title, sql, x, y, w, h=8, session_link=False, sort=None, desc=""):
    p = panel("table", title, sql, x, y, w, h, desc=desc)
    p["options"] = {"showHeader": True, "cellHeight": "sm"}
    if sort:
        p["options"]["sortBy"] = [{"displayName": sort, "desc": True}]
    if session_link:
        p["fieldConfig"]["overrides"].append({"matcher": {"id": "byName", "options": "session"}, "properties": [
            {"id": "links", "value": [{"title": "Open session", "url": SESSION_URL}]}]})
    return p


def geomap(title, sql, x, y, w, h):
    p = panel("geomap", title, sql, x, y, w, h)
    p["options"] = {"view": {"id": "zero", "lat": 20, "lon": 0, "zoom": 1},
                    "controls": {"showZoom": True, "mouseWheelZoom": True},
                    "tooltip": {"mode": "details"},
                    "basemap": {"type": "osm-standard", "name": "OpenStreetMap"},
                    "layers": [{"type": "markers", "name": "Attack sources", "tooltip": True,
                                "location": {"mode": "coords", "latitude": "lat", "longitude": "lon"},
                                "config": {"showLegend": False, "style": {
                                    "color": {"fixed": "red"}, "opacity": 0.6, "symbol": {"fixed": "img/icons/marker/circle.svg", "mode": "fixed"},
                                    "size": {"field": "connections", "min": 4, "max": 24, "fixed": 6}}}}]}
    return p


def dashboard(uid, title, panels, **extra):
    d = {"uid": uid, "title": title, "schemaVersion": 39, "version": 1, "editable": False, "timezone": "browser",
         "refresh": "5m", "time": {"from": "now-7d", "to": "now"}, "panels": panels, "tags": ["honeypot"],
         "templating": {"list": []}, "annotations": {"list": []}}
    d.update(extra)
    return d


T = "$__timeFilter(ts)"
overview = [
    stat("Connections", f"SELECT count(*) FROM events WHERE eventid='cowrie.session.connect' AND {T}", 0),
    stat("Unique IPs", f"SELECT count(DISTINCT src_ip) FROM events WHERE eventid='cowrie.session.connect' AND {T}", 4),
    stat("Successful logins", f"SELECT count(*) FROM events WHERE eventid='cowrie.login.success' AND {T}", 8),
    stat("Failed logins", f"SELECT count(*) FROM events WHERE eventid='cowrie.login.failed' AND {T}", 12),
    stat("Commands", f"SELECT count(*) FROM events WHERE eventid='cowrie.command.input' AND {T}", 16),
    stat("Files captured", f"SELECT count(DISTINCT shasum) FROM events WHERE eventid IN ('cowrie.session.file_download','cowrie.session.file_upload') AND {T}", 20),
    series("Connections over time, by protocol", f"SELECT $__timeGroup(ts, $__interval, 0) AS time, protocol AS metric, count(*) AS value FROM events WHERE eventid='cowrie.session.connect' AND {T} GROUP BY 1, 2 ORDER BY 1", 0, 4, 12, style="bars"),
    series("Logins and commands over time", f"SELECT $__timeGroup(ts, $__interval, 0) AS time, replace(eventid, 'cowrie.', '') AS metric, count(*) AS value FROM events WHERE eventid IN ('cowrie.login.success','cowrie.login.failed','cowrie.command.input') AND {T} GROUP BY 1, 2 ORDER BY 1", 12, 4, 12, style="bars"),
    geomap("Where connections come from", f"SELECT g.lat, g.lon, g.city, g.country, count(*) AS connections, count(DISTINCT e.src_ip) AS ips FROM events e JOIN ip_geo g ON g.ip = e.src_ip WHERE e.eventid='cowrie.session.connect' AND g.lat IS NOT NULL AND {T.replace('ts', 'e.ts')} GROUP BY 1, 2, 3, 4", 0, 12, 14, 12),
    table("Top countries", f"SELECT coalesce(g.country, 'Unknown') AS country, count(*) AS connections, count(DISTINCT e.src_ip) AS ips FROM events e LEFT JOIN ip_geo g ON g.ip = e.src_ip WHERE e.eventid='cowrie.session.connect' AND {T.replace('ts', 'e.ts')} GROUP BY 1 ORDER BY 2 DESC LIMIT 25", 14, 12, 10, 12),
    table("Top source IPs", f"SELECT e.src_ip AS ip, coalesce(g.country, 'Unknown') AS country, count(*) AS connections FROM events e LEFT JOIN ip_geo g ON g.ip = e.src_ip WHERE e.eventid='cowrie.session.connect' AND {T.replace('ts', 'e.ts')} GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 25", 0, 24, 8),
    table("Top username:password pairs", f"SELECT username, password, count(*) AS attempts FROM events WHERE eventid IN ('cowrie.login.success','cowrie.login.failed') AND {T} GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 25", 8, 24, 8),
    table("Top SSH client versions", f"SELECT client_version, count(*) AS connections FROM events WHERE eventid='cowrie.client.version' AND {T} GROUP BY 1 ORDER BY 2 DESC LIMIT 25", 16, 24, 8),
    table("Top commands", f"SELECT input AS command, count(*) AS times FROM events WHERE eventid='cowrie.command.input' AND {T} GROUP BY 1 ORDER BY 2 DESC LIMIT 25", 0, 32, 12),
    table("Captured files", f"SELECT min(ts) AS first_seen, shasum, count(*) AS times, max(coalesce(url, filename)) AS source FROM events WHERE eventid IN ('cowrie.session.file_download','cowrie.session.file_upload') AND shasum IS NOT NULL AND {T} GROUP BY 2 ORDER BY 1 DESC LIMIT 50", 12, 32, 12),
    table("Sessions: click an ID for details", "SELECT s.started, s.session, s.protocol, s.src_ip, coalesce(g.country, 'Unknown') AS country, s.logged_in, s.username, s.password, s.failed_logins, s.commands, s.files, round(s.duration_s::numeric, 1) AS seconds FROM sessions s LEFT JOIN ip_geo g ON g.ip = s.src_ip WHERE $__timeFilter(s.started) ORDER BY s.logged_in DESC, s.started DESC LIMIT 200", 0, 40, 24, 12, session_link=True),
    panel("text", "", "SELECT 1", 0, 52, 24, 2),
]
overview[-1].pop("targets"); overview[-1].pop("datasource")
overview[-1]["options"] = {"mode": "markdown", "content": "Times are local to your browser. Locations are approximate: [IP Geolocation by DB-IP](https://db-ip.com) (CC BY 4.0). Source IPs are usually other hacked devices, not the people behind an attack."}

Q = "${session:sqlstring}"
_next[0] = 100
session = [
    table("Session", f"SELECT s.session, s.started, s.protocol, s.src_ip, g.country, g.city, s.logged_in, s.username, s.password, s.failed_logins, s.commands, s.files, round(s.duration_s::numeric, 1) AS seconds FROM sessions s LEFT JOIN ip_geo g ON g.ip = s.src_ip WHERE s.session = {Q}", 0, 0, 24, 4),
    table("Timeline", f"SELECT ts AS time, replace(eventid, 'cowrie.', '') AS event, coalesce(input, url, CASE WHEN username IS NOT NULL THEN username || ':' || coalesce(password, '') END, client_version, filename, CASE WHEN duration_s IS NOT NULL THEN round(duration_s::numeric, 1)::text || ' seconds' END, '') AS detail, coalesce(shasum, '') AS sha256 FROM events WHERE session = {Q} ORDER BY ts", 0, 4, 24, 16),
    table("Replay it on the Pi", f"SELECT 'cowrie-stats replay ' || {Q} AS command", 0, 20, 24, 3, desc="Terminal recordings stay on the Pi."),
]
variable = {"name": "session", "label": "Session", "type": "query", "datasource": DS, "refresh": 1, "sort": 0,
            "query": "SELECT session FROM sessions ORDER BY started DESC LIMIT 500", "definition": "SELECT session FROM sessions ORDER BY started DESC LIMIT 500",
            "includeAll": False, "multi": False}

OUT.mkdir(exist_ok=True)
(OUT / "overview.json").write_text(json.dumps(dashboard("honeypot-overview", "Honeypot overview", overview), indent=1) + "\n")
(OUT / "session.json").write_text(json.dumps(dashboard("honeypot-session", "Session", session, templating={"list": [variable]}, time={"from": "now-90d", "to": "now"}), indent=1) + "\n")
print("wrote", sorted(p.name for p in OUT.glob("*.json")))
