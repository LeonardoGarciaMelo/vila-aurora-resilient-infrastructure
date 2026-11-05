-- Hardened cloud database. Synthetic data only (RT-19).
CREATE TABLE sites (
  id   TEXT PRIMARY KEY,
  name TEXT NOT NULL
);

CREATE TABLE readings (
  device_id TEXT NOT NULL,
  seq       BIGINT NOT NULL,
  site      TEXT NOT NULL,
  metric    TEXT NOT NULL,
  value     DOUBLE PRECISION,
  read_at   TIMESTAMPTZ NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, seq)
);
CREATE INDEX readings_site_time ON readings (site, read_at DESC);

CREATE TABLE users (
  id            SERIAL PRIMARY KEY,
  username      TEXT UNIQUE NOT NULL,
  display_name  TEXT NOT NULL,
  email         TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('operator','technician','coordination','auditor')),
  password_hash TEXT NOT NULL,
  totp_secret   TEXT NOT NULL,
  active        BOOLEAN NOT NULL DEFAULT true
);

-- Pseudonymised access history: badge_hash = HMAC-SHA256(badge_id, key)
CREATE TABLE access_logs (
  id         BIGSERIAL PRIMARY KEY,
  happened_at TIMESTAMPTZ NOT NULL,
  location   TEXT NOT NULL,
  badge_hash TEXT NOT NULL,
  result     TEXT NOT NULL
);

CREATE TABLE alerts (
  id         BIGSERIAL PRIMARY KEY,
  site       TEXT NOT NULL,
  severity   TEXT NOT NULL,
  message    TEXT NOT NULL,
  raised_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  acked_by   TEXT,
  acked_at   TIMESTAMPTZ
);

CREATE TABLE audit_log (
  id         BIGSERIAL PRIMARY KEY,
  at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  username   TEXT NOT NULL,
  action     TEXT NOT NULL,
  detail     TEXT NOT NULL,
  source_ip  TEXT
);

CREATE TABLE pending_actions (
  id           BIGSERIAL PRIMARY KEY,
  site         TEXT NOT NULL,
  actuator     TEXT NOT NULL,
  action       TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  approved_by  TEXT,
  decided_at   TIMESTAMPTZ,
  status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected'))
);

INSERT INTO sites VALUES
  ('centro', 'Centro Comunitário'), ('escola', 'Escola Municipal'), ('ubs', 'UBS'),
  ('horta', 'Horta e Cozinha Solidária'), ('abrigo', 'Abrigo de Emergência');
