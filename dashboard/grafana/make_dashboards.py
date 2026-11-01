#!/usr/bin/env python3
"""Generate the Grafana dashboards in grafana/dashboards/. Run after editing."""
import base64
import json
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent / "dashboards"
DS = {"type": "grafana-postgresql-datasource", "uid": "honeypot-pg"}
SESSION_URL = "/d/honeypot-session/session?var-session=${__value.raw}&from=now-90d&to=now"
SAMPLE_URL = "/d/honeypot-sample/sample?var-sample=${__value.raw}&from=now-90d&to=now"
CONNECT = "eventid='cowrie.session.connect'"
LOGIN_OK = "eventid='cowrie.login.success'"
LOGIN_BAD = "eventid='cowrie.login.failed'"
COMMAND = "eventid='cowrie.command.input'"
FILES = "eventid IN ('cowrie.session.file_download','cowrie.session.file_upload')"
T = "$__timeFilter(ts)"
ET = "$__timeFilter(e.ts)"
BLUE, GREEN, RED, ORANGE, PURPLE, CYAN, GRAY = "#5794f2", "#73bf69", "#f2495c", "#ff9830", "#b877d9", "#5ad4e6", "#8e8e8e"


class Ids:
    """Hands out panel ids and keeps track of the next free row."""

    def __init__(self, start=1):
        self.value = start - 1

    def next(self):
        self.value += 1
        return self.value


ids = Ids()


def fixed(color):
    return {"mode": "fixed", "fixedColor": color}


def panel(kind, title, sql, x, y, w, h, fmt="table", desc=""):
    item = {"id": ids.next(), "type": kind, "title": title, "description": desc,
            "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "fieldConfig": {"defaults": {}, "overrides": []}, "options": {}}
    if sql:
        item["datasource"] = DS
        item["targets"] = [{"refId": "A", "datasource": DS, "rawQuery": True, "rawSql": sql,
                            "format": fmt, "editorMode": "code"}]
    return item


def row(title, y):
    return {"id": ids.next(), "type": "row", "title": title, "collapsed": False,
            "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}, "panels": []}


def trend(title, where, x, y, w, color, desc=""):
    """Number tile with a small hourly trend line; shows the total for the time range."""
    sql = f"SELECT $__timeGroup(ts, '1h', 0) AS time, count(*) AS value FROM events WHERE {where} AND {T} GROUP BY 1 ORDER BY 1"
    p = panel("stat", title, sql, x, y, w, 5, fmt="time_series", desc=desc)
    p["options"] = {"reduceOptions": {"calcs": ["sum"], "fields": "", "values": False},
                    "colorMode": "value", "graphMode": "area", "textMode": "value", "justifyMode": "auto"}
    p["fieldConfig"]["defaults"] = {"noValue": "0", "color": fixed(color), "decimals": 0}
    return p


def tile(title, sql, x, y, w, color=BLUE, unit=None, thresholds=None, desc="", decimals=0):
    p = panel("stat", title, sql, x, y, w, 3, desc=desc)
    p["options"] = {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                    "colorMode": "value", "graphMode": "none", "textMode": "value", "justifyMode": "auto"}
    defaults = {"noValue": "0" if unit != "dateTimeFromNow" else "none yet", "decimals": decimals}
    if thresholds:
        defaults["color"] = {"mode": "thresholds"}
        defaults["thresholds"] = {"mode": "absolute", "steps": thresholds}
    else:
        defaults["color"] = fixed(color)
    if unit:
        defaults["unit"] = unit
    p["fieldConfig"]["defaults"] = defaults
    return p


def bars(title, sql, x, y, w, colors, h=8):
    p = panel("timeseries", title, sql, x, y, w, h, fmt="time_series")
    p["interval"] = "5m"
    p["fieldConfig"]["defaults"] = {"custom": {"drawStyle": "bars", "fillOpacity": 80, "lineWidth": 0,
                                               "stacking": {"mode": "normal"}, "showPoints": "never"},
                                    "min": 0, "decimals": 0}
    p["fieldConfig"]["overrides"] = [{"matcher": {"id": "byName", "options": name},
                                      "properties": [{"id": "color", "value": fixed(color)}]}
                                     for name, color in colors.items()]
    p["options"] = {"legend": {"displayMode": "table", "placement": "bottom", "showLegend": True, "calcs": ["sum"]},
                    "tooltip": {"mode": "multi", "sort": "desc"}}
    return p


def column(name, *properties):
    return {"matcher": {"id": "byName", "options": name},
            "properties": [{"id": k, "value": v} for k, v in properties]}


def meter(name, color, width=170):
    """Count column drawn as a bar, so top lists can be read at a glance."""
    return column(name, ("custom.cellOptions", {"type": "gauge", "mode": "basic", "valueDisplayMode": "text"}),
                  ("color", fixed(color)), ("custom.width", width), ("decimals", 0))


def stamp(name, width=150):
    return column(name, ("unit", "time: MM-DD HH:mm:ss"), ("custom.width", width))


def table(title, sql, x, y, w, h=9, overrides=(), desc=""):
    p = panel("table", title, sql, x, y, w, h, desc=desc)
    p["options"] = {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}}
    p["fieldConfig"]["defaults"] = {"custom": {"align": "auto", "filterable": False}}
    p["fieldConfig"]["overrides"] = list(overrides)
    return p


def blank_tile():
    """A 1x1 dark PNG. The map uses it instead of a tile server, so nothing is fetched."""
    def chunk(tag, data):
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)) \
        + chunk(b"IDAT", zlib.compress(b"\x00\x11\x12\x17")) + chunk(b"IEND", b"")
    return "data:image/png;base64," + base64.b64encode(png).decode()


def attack_map(title, sql, x, y, w, h):
    p = panel("geomap", title, sql, x, y, w, h)
    p["fieldConfig"]["defaults"] = {"color": fixed(RED)}
    p["options"] = {
        "view": {"id": "coords", "lat": 25, "lon": 10, "zoom": 1.3},
        "controls": {"showZoom": True, "mouseWheelZoom": True, "showAttribution": False},
        "tooltip": {"mode": "details"},
        "basemap": {"type": "xyz", "name": "Dark background", "config": {"url": blank_tile(), "attribution": ""}},
        "layers": [
            {"type": "geojson", "name": "Countries", "tooltip": False,
             "config": {"src": "public/maps/countries.geojson", "rules": [], "idField": "id",
                        "style": {"color": {"fixed": "#2c3235"}, "opacity": 1, "lineWidth": 1,
                                  "symbol": {"fixed": "", "mode": "fixed"},
                                  "size": {"fixed": 5, "min": 2, "max": 15},
                                  "rotation": {"fixed": 0, "mode": "mod", "min": -360, "max": 360},
                                  "symbolAlign": {"horizontal": "center", "vertical": "center"},
                                  "textConfig": {"fontSize": 12, "offsetX": 0, "offsetY": 0,
                                                 "textAlign": "center", "textBaseline": "middle"}}}},
            {"type": "markers", "name": "Attack sources", "tooltip": True,
             "location": {"mode": "coords", "latitude": "lat", "longitude": "lon"},
             "config": {"showLegend": False, "style": {
                 "color": {"fixed": RED}, "opacity": 0.65,
                 "symbol": {"fixed": "img/icons/marker/circle.svg", "mode": "fixed"},
                 "size": {"field": "connections", "min": 5, "max": 26, "fixed": 6}}}},
        ]}
    return p


def dashboard(uid, title, panels, **extra):
    d = {"uid": uid, "title": title, "schemaVersion": 39, "version": 1, "editable": False, "timezone": "",
         "refresh": "5m", "time": {"from": "now-24h", "to": "now"}, "panels": panels, "tags": ["honeypot"],
         "graphTooltip": 1, "templating": {"list": []}, "annotations": {"list": []},
         "timepicker": {"refresh_intervals": ["1m", "5m", "15m", "1h"]}}
    d.update(extra)
    return d


# ---------------------------------------------------------------- overview
overview = [
    row("Overview", 0),
    trend("Connections", CONNECT, 0, 1, 5, BLUE),
    tile("Unique IPs", f"SELECT count(DISTINCT src_ip) FROM events WHERE {CONNECT} AND {T}", 5, 1, 4, PURPLE),
    trend("Successful logins", LOGIN_OK, 9, 1, 5, GREEN),
    trend("Failed logins", LOGIN_BAD, 14, 1, 5, ORANGE),
    trend("Commands run", COMMAND, 19, 1, 5, CYAN),
    tile("New IPs (24h)",
         f"SELECT count(*) FROM (SELECT src_ip FROM events WHERE {CONNECT} GROUP BY src_ip "
         "HAVING min(ts) >= now() - interval '24 hours') t", 5, 4, 4, PURPLE,
         desc="IPs seen for the first time in the last 24 hours, whatever time range is selected."),
    tile("Login success rate",
         f"SELECT round(100.0 * count(*) FILTER (WHERE {LOGIN_OK}) / nullif(count(*), 0), 1) "
         f"FROM events WHERE ({LOGIN_OK} OR {LOGIN_BAD}) AND {T}", 0, 6, 5, GREEN, unit="percent", decimals=1,
         desc="Cowrie accepts most passwords on purpose, so a high rate is normal for a honeypot."),
    tile("Files captured", f"SELECT count(DISTINCT shasum) FROM events WHERE {FILES} AND {T}", 9, 6, 5,
         thresholds=[{"color": GREEN, "value": None}, {"color": RED, "value": 1}],
         desc="Distinct files by SHA-256. Red means there are samples to look at."),
    tile("Last activity", "SELECT extract(epoch FROM max(ts)) * 1000 AS value FROM events", 14, 6, 5, BLUE,
         unit="dateTimeFromNow", desc="Newest event pulled from the Pi, whatever time range is selected."),
    tile("Sessions with commands",
         f"SELECT count(DISTINCT session) FROM events WHERE {COMMAND} AND {T}", 19, 6, 5, CYAN),
    bars("Connections over time, by protocol",
         f"SELECT $__timeGroup(ts, $__interval, 0) AS time, protocol AS metric, count(*) AS value FROM events "
         f"WHERE {CONNECT} AND {T} GROUP BY 1, 2 ORDER BY 1", 0, 9, 12, {"ssh": BLUE, "telnet": ORANGE}),
    bars("Logins and commands over time",
         "SELECT $__timeGroup(ts, $__interval, 0) AS time, replace(eventid, 'cowrie.', '') AS metric, count(*) AS value "
         f"FROM events WHERE ({LOGIN_OK} OR {LOGIN_BAD} OR {COMMAND}) AND {T} GROUP BY 1, 2 ORDER BY 1", 12, 9, 12,
         {"login.success": GREEN, "login.failed": ORANGE, "command.input": CYAN}),

    row("Malware and sessions", 17),
    table("Captured files: click a sha256 to read it or a session for details",
          "SELECT min(ts) AS first_seen, session, "
          "CASE WHEN eventid LIKE '%upload' THEN 'pushed' ELSE 'fetched' END AS how, src_ip, "
          "CASE WHEN shasum LIKE 'e3b0c44298fc1c149afbf4c8996fb924%' THEN 'empty file' ELSE coalesce(url, filename, 'not logged') END AS source, "
          f"shasum AS sha256 FROM events WHERE {FILES} AND shasum IS NOT NULL AND {T} "
          "GROUP BY session, eventid, src_ip, shasum, url, filename ORDER BY 1 DESC LIMIT 50", 0, 18, 24, 6,
          [stamp("first_seen"),
           column("session", ("links", [{"title": "Open session", "url": SESSION_URL}]), ("custom.width", 130)),
           column("how", ("custom.width", 80)), column("src_ip", ("custom.width", 140)),
           column("sha256", ("links", [{"title": "Read file and look it up", "url": SAMPLE_URL}]), ("custom.width", 480))],
          desc="Click a sha256 to read scripts and look files up. fetched: an attacker's command made the honeypot download it. pushed: sent directly (SCP/SFTP). The files stay on the Pi."),
    table("Sessions: logged-in first, click an ID for details",
          "SELECT s.started, s.session, s.protocol, s.src_ip, coalesce(g.country, 'Unknown') AS country, s.logged_in, "
          "s.username, s.password, s.commands, s.files, round(s.duration_s::numeric, 1) AS seconds "
          "FROM sessions s LEFT JOIN ip_geo g ON g.ip = s.src_ip WHERE $__timeFilter(s.started) "
          "ORDER BY s.logged_in DESC, s.started DESC LIMIT 200", 0, 24, 24, 12,
          [stamp("started"),
           column("session", ("links", [{"title": "Open session", "url": SESSION_URL}]), ("custom.width", 130)),
           column("protocol", ("custom.width", 80)), column("src_ip", ("custom.width", 140)),
           column("logged_in", ("custom.width", 90), ("custom.cellOptions", {"type": "color-text"}),
                  ("mappings", [{"type": "value", "options": {
                      "true": {"text": "yes", "color": GREEN, "index": 0},
                      "false": {"text": "no", "color": GRAY, "index": 1}}}])),
           meter("commands", CYAN, 130),
           column("files", ("custom.width", 70), ("custom.cellOptions", {"type": "color-text"}),
                  ("color", {"mode": "thresholds"}),
                  ("thresholds", {"mode": "absolute", "steps": [{"color": GRAY, "value": None}, {"color": RED, "value": 1}]})),
           column("seconds", ("custom.width", 80))]),

    row("Origins", 36),
    attack_map("Where connections come from",
               f"SELECT g.lat, g.lon, g.city, g.country, count(*) AS connections, count(DISTINCT e.src_ip) AS ips "
               f"FROM events e JOIN ip_geo g ON g.ip = e.src_ip WHERE e.{CONNECT} AND g.lat IS NOT NULL AND {ET} "
               "GROUP BY 1, 2, 3, 4", 0, 37, 14, 13),
    table("Top countries",
          f"SELECT coalesce(g.country, 'Unknown') AS country, count(*) AS connections, count(DISTINCT e.src_ip) AS ips "
          f"FROM events e LEFT JOIN ip_geo g ON g.ip = e.src_ip WHERE e.{CONNECT} AND {ET} "
          "GROUP BY 1 ORDER BY 2 DESC LIMIT 25", 14, 37, 10, 6,
          [meter("connections", BLUE), column("ips", ("custom.width", 70))]),
    table("Top source IPs",
          f"SELECT e.src_ip AS ip, coalesce(g.country, 'Unknown') AS country, count(*) AS connections, max(e.ts) AS last_seen "
          f"FROM events e LEFT JOIN ip_geo g ON g.ip = e.src_ip WHERE e.{CONNECT} AND {ET} "
          "GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 25", 14, 43, 10, 7,
          [meter("connections", BLUE, 140), stamp("last_seen", 130), column("ip", ("custom.width", 135))],
          desc="Usually other hacked devices, not the people behind an attack."),

    row("Attacker behavior", 50),
    table("Top commands",
          f"SELECT input AS command, count(*) AS times FROM events WHERE {COMMAND} AND {T} GROUP BY 1 ORDER BY 2 DESC LIMIT 25",
          0, 51, 12, 11, [meter("times", CYAN, 130)]),
    table("Top username:password pairs",
          f"SELECT username, password, count(*) AS attempts FROM events WHERE ({LOGIN_OK} OR {LOGIN_BAD}) AND {T} "
          "GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 25", 12, 51, 6, 11, [meter("attempts", ORANGE, 110)]),
    table("Top SSH client versions",
          f"SELECT client_version AS client, count(*) AS connections FROM events WHERE eventid='cowrie.client.version' AND {T} "
          "GROUP BY 1 ORDER BY 2 DESC LIMIT 25", 18, 51, 6, 11, [meter("connections", PURPLE, 110)]),
]
note = panel("text", "", None, 0, 62, 24, 2)
note["options"] = {"mode": "markdown", "content": (
    "Times use the timezone in COWRIE_LOG_TZ. Locations are approximate: "
    "[IP Geolocation by DB-IP](https://db-ip.com) (CC BY 4.0).")}
note["transparent"] = True
overview.append(note)

# ----------------------------------------------------------------- session
ids = Ids(100)
Q = "${session:sqlstring}"
EVENT_COLORS = {"command.input": CYAN, "login.success": GREEN, "login.failed": ORANGE,
                "session.file_download": RED, "session.file_upload": RED, "session.connect": BLUE,
                "session.closed": GRAY, "log.closed": GRAY, "client.version": PURPLE}
facts = table("Session",
              "SELECT s.started, s.src_ip, coalesce(g.country, 'Unknown') AS country, coalesce(g.city, 'Unknown') AS city, s.protocol, "
              "CASE WHEN s.logged_in THEN coalesce(s.username, '') || ':' || coalesce(s.password, '') ELSE 'no login' END AS login, "
              "s.commands, s.files, round(s.duration_s::numeric, 1) AS seconds "
              f"FROM sessions s LEFT JOIN ip_geo g ON g.ip = s.src_ip WHERE s.session = {Q}", 0, 0, 24, 4,
              [stamp("started"), column("src_ip", ("custom.width", 150)), column("protocol", ("custom.width", 90)),
               column("commands", ("custom.width", 100)), column("files", ("custom.width", 70)),
               column("seconds", ("custom.width", 80))])
replay = panel("text", "", None, 0, 22, 24, 2)
replay["options"] = {"mode": "markdown", "content": (
    "Watch this session as a recording on the Pi: `cowrie-stats replay $session`. "
    "Recordings and captured files stay on the Pi.")}
replay["transparent"] = True
session = [
    facts,
    table("Timeline",
          "SELECT ts AS time, replace(eventid, 'cowrie.', '') AS event, "
          "coalesce(input, url, CASE WHEN username IS NOT NULL THEN username || ':' || coalesce(password, '') END, "
          "client_version, filename, CASE WHEN duration_s IS NOT NULL THEN round(duration_s::numeric, 1)::text || ' seconds' END, '') AS detail, "
          f"coalesce(shasum, '') AS sha256 FROM events WHERE session = {Q} "
          "AND eventid IN ('cowrie.session.connect','cowrie.client.version','cowrie.login.success','cowrie.login.failed',"
          "'cowrie.command.input','cowrie.session.file_download','cowrie.session.file_upload','cowrie.session.closed') "
          "ORDER BY ts", 0, 4, 24, 18,
          [stamp("time", 140),
           column("event", ("custom.width", 190), ("custom.cellOptions", {"type": "color-text"}),
                  ("mappings", [{"type": "value", "options": {
                      name: {"color": color, "index": i} for i, (name, color) in enumerate(EVENT_COLORS.items())}}])),
           column("sha256", ("links", [{"title": "Read file and look it up", "url": SAMPLE_URL}]), ("custom.width", 540))]),
    replay,
]
# ------------------------------------------------------------------ sample
ids = Ids(200)
S = "${sample:sqlstring}"
buttons = panel("text", "Look up this hash", None, 0, 0, 24, 3)
buttons["options"] = {"mode": "markdown", "content": (
    "**[Look up on VirusTotal](https://www.virustotal.com/gui/file/$sample)** &nbsp;&nbsp;|&nbsp;&nbsp; "
    "**[Look up on MalwareBazaar](https://bazaar.abuse.ch/browse.php?search=sha256%3A$sample)**\n\n"
    "These send only the hash, and only when clicked. No file is uploaded.")}
contents = panel("logs", "File contents: read only, never run this",
                 "SELECT to_timestamp(t.line_number) AS time, "
                 "CASE WHEN t.line_text = '' THEN ' ' ELSE t.line_text END AS text FROM samples s, "
                 "regexp_split_to_table(s.content, E'\\n') WITH ORDINALITY AS t(line_text, line_number) "
                 f"WHERE s.sha256 = {S} ORDER BY t.line_number", 0, 8, 24, 28,
                 desc="Empty means the file is a binary or too large, or is empty. Those stay on the Pi. Attacker text: treat it as hostile.")
contents["options"] = {"showTime": False, "showLabels": False, "showCommonLabels": False, "wrapLogMessage": True,
                       "prettifyLogMessage": False, "enableLogDetails": False, "dedupStrategy": "none",
                       "sortOrder": "Ascending"}
sample = [
    buttons,
    table("Delivered by",
          "SELECT min(ts) AS first_seen, session, CASE WHEN eventid LIKE '%upload' THEN 'pushed' ELSE 'fetched' END AS how, src_ip, "
          f"coalesce(url, filename, 'not logged') AS source FROM events WHERE shasum = {S} AND {FILES} "
          "GROUP BY session, eventid, src_ip, url, filename ORDER BY 1 DESC", 0, 3, 24, 5,
          [stamp("first_seen"),
           column("session", ("links", [{"title": "Open session", "url": SESSION_URL}]), ("custom.width", 130)),
           column("how", ("custom.width", 80)), column("src_ip", ("custom.width", 140))]),
    contents,
]
sample_variable = {"name": "sample", "label": "File (SHA-256)", "type": "query", "datasource": DS, "refresh": 1, "sort": 0,
                   "query": f"SELECT shasum FROM events WHERE {FILES} AND shasum IS NOT NULL GROUP BY shasum ORDER BY max(ts) DESC LIMIT 500",
                   "definition": "captured files, newest first", "includeAll": False, "multi": False}

variable = {"name": "session", "label": "Session", "type": "query", "datasource": DS, "refresh": 1, "sort": 0,
            "query": "SELECT session FROM sessions ORDER BY started DESC LIMIT 500",
            "definition": "SELECT session FROM sessions ORDER BY started DESC LIMIT 500",
            "includeAll": False, "multi": False}

OUT.mkdir(exist_ok=True)
(OUT / "overview.json").write_text(json.dumps(dashboard("honeypot-overview", "Honeypot overview", overview), indent=1) + "\n")
(OUT / "session.json").write_text(json.dumps(dashboard(
    "honeypot-session", "Session", session, templating={"list": [variable]},
    time={"from": "now-90d", "to": "now"}), indent=1) + "\n")
(OUT / "sample.json").write_text(json.dumps(dashboard(
    "honeypot-sample", "Sample", sample, templating={"list": [sample_variable]},
    time={"from": "now-90d", "to": "now"}), indent=1) + "\n")
print("wrote", sorted(p.name for p in OUT.glob("*.json")))
