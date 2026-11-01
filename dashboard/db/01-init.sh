#!/bin/sh
set -eu
psql -v ON_ERROR_STOP=1 -v ro_pw="$GRAFANA_DB_PASSWORD" -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<'SQL'
CREATE TABLE events (
  id             text PRIMARY KEY,      -- SHA-256 of the raw log line: re-ingesting is harmless
  ts             timestamptz NOT NULL,
  eventid        text NOT NULL,
  session        text,
  src_ip         text,
  dst_port       integer,
  protocol       text,
  sensor         text,
  username       text,
  password       text,
  input          text,
  url            text,
  shasum         text,
  filename       text,
  client_version text,
  duration_s     double precision
);
CREATE INDEX events_ts ON events (ts);
CREATE INDEX events_session ON events (session);
CREATE INDEX events_eventid_ts ON events (eventid, ts);

CREATE TABLE ip_geo (
  ip text PRIMARY KEY, country_code text, country text, city text,
  lat double precision, lon double precision
);

CREATE TABLE ingest_files (name text PRIMARY KEY, size bigint, mtime double precision);

CREATE VIEW sessions AS
SELECT session,
       min(ts) AS started,
       max(src_ip) FILTER (WHERE eventid = 'cowrie.session.connect') AS src_ip,
       max(protocol) FILTER (WHERE eventid = 'cowrie.session.connect') AS protocol,
       max(sensor) AS sensor,
       bool_or(eventid = 'cowrie.login.success') AS logged_in,
       max(username) FILTER (WHERE eventid = 'cowrie.login.success') AS username,
       max(password) FILTER (WHERE eventid = 'cowrie.login.success') AS password,
       count(*) FILTER (WHERE eventid = 'cowrie.login.failed') AS failed_logins,
       count(*) FILTER (WHERE eventid = 'cowrie.command.input') AS commands,
       count(*) FILTER (WHERE eventid IN ('cowrie.session.file_download','cowrie.session.file_upload')) AS files,
       max(duration_s) FILTER (WHERE eventid = 'cowrie.session.closed') AS duration_s
FROM events WHERE session IS NOT NULL GROUP BY session;

CREATE ROLE grafana_ro LOGIN PASSWORD :'ro_pw';
GRANT CONNECT ON DATABASE honeypot TO grafana_ro;
GRANT USAGE ON SCHEMA public TO grafana_ro;
GRANT SELECT ON events, ip_geo, sessions TO grafana_ro;
SQL
