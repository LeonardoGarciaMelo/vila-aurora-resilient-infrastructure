#!/bin/bash
# Least-privilege roles (RT-08). Passwords arrive through the environment, never from the repo.
set -euo pipefail
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v ingest_pw="$INGEST_DB_PASSWORD" -v panel_pw="$PANEL_DB_PASSWORD" -v auth_pw="$AUTH_DB_PASSWORD" -v ai_pw="$AI_DB_PASSWORD" <<'SQL'
CREATE ROLE ingest_app LOGIN PASSWORD :'ingest_pw';
CREATE ROLE panel_app  LOGIN PASSWORD :'panel_pw';
CREATE ROLE auth_app   LOGIN PASSWORD :'auth_pw';
CREATE ROLE ai_app     LOGIN PASSWORD :'ai_pw';

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ingest_app, panel_app, auth_app, ai_app;
GRANT SELECT ON readings TO ai_app;

GRANT SELECT, INSERT ON readings TO ingest_app;
GRANT INSERT ON alerts TO ingest_app;
GRANT USAGE ON SEQUENCE alerts_id_seq TO ingest_app;

GRANT SELECT ON sites, readings, access_logs TO panel_app;
GRANT SELECT ON alerts TO panel_app;
GRANT UPDATE (acked_by, acked_at) ON alerts TO panel_app;
GRANT SELECT, INSERT ON audit_log TO panel_app;
GRANT SELECT, INSERT ON pending_actions TO panel_app;
GRANT UPDATE (approved_by, decided_at, status) ON pending_actions TO panel_app;
GRANT USAGE ON SEQUENCE audit_log_id_seq, pending_actions_id_seq TO panel_app;

-- Only the authentication service can read the users table.
GRANT SELECT ON users TO auth_app;
GRANT UPDATE (active) ON users TO auth_app;
SQL
