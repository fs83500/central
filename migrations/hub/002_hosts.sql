-- UnifiedGuard — HUB migration 002: enrollment tokens, hosts, telemetry.
-- Tokens are stored HASHED (SHA-256): enough for 128-bit random tokens;
-- Argon2id is for weak passwords, not for high-entropy tokens.
-- Hosts are INSERT-at-enroll then UPDATE-only by the app; revocation via
-- revoked_at + cert_serial (CRL equivalent, SPEC §6.1).

CREATE TABLE IF NOT EXISTS enroll_tokens (
    id           BIGSERIAL PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,       -- SHA-256 hex of the raw token
    label        TEXT NOT NULL DEFAULT '',
    expires_at   TIMESTAMPTZ NOT NULL,
    used_at      TIMESTAMPTZ,
    used_by_host TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by   TEXT NOT NULL DEFAULT 'system'
);

CREATE TABLE IF NOT EXISTS host_groups (
    id            BIGSERIAL PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    color         TEXT NOT NULL DEFAULT '#4f8cff',
    maint_default JSONB NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS hosts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname      TEXT NOT NULL,
    friendly_name TEXT NOT NULL DEFAULT '',
    os           TEXT NOT NULL DEFAULT '',
    os_version    TEXT NOT NULL DEFAULT '',
    arch         TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    agent_hash   TEXT NOT NULL DEFAULT '',    -- N12 self-hash
    fw_type      TEXT NOT NULL DEFAULT '',
    fw_backend   TEXT NOT NULL DEFAULT '',
    fw_version   TEXT NOT NULL DEFAULT '',
    fw_active    BOOLEAN NOT NULL DEFAULT FALSE,
    group_id     BIGINT REFERENCES host_groups(id),
    status       TEXT NOT NULL DEFAULT 'offline',   -- online / stale / offline (derived)
    last_seen    TIMESTAMPTZ,
    rtt_ms       INT,
    cert_serial  TEXT NOT NULL DEFAULT '',
    enrolled_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS hosts_hostname_idx ON hosts (hostname);
CREATE INDEX IF NOT EXISTS hosts_status_idx ON hosts (status);

-- Telemetry rows, partitioning postponed (J2, per plan §2.2).
CREATE TABLE IF NOT EXISTS telemetry (
    host_id   UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    ts        TIMESTAMPTZ NOT NULL DEFAULT now(),
    cpu_pct   REAL NOT NULL,
    mem_pct   REAL NOT NULL,
    load1     REAL NOT NULL,
    uptime_s  BIGINT NOT NULL,
    disks     JSONB NOT NULL DEFAULT '[]',
    net       JSONB NOT NULL DEFAULT '[]',
    services  JSONB NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS telemetry_host_ts_idx ON telemetry (host_id, ts DESC);