-- UnifiedGuard — FLEET migration 001: users, email tokens (double opt-in),
-- login attempts. The fleet's own audit chain arrives with migration 005;
-- this file bootstraps accounts.

CREATE TABLE IF NOT EXISTS users (
    id              BIGSERIAL PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    email_verified  BOOLEAN NOT NULL DEFAULT FALSE,
    password_hash   TEXT NOT NULL,             -- Argon2id
    is_dpnac_admin  BOOLEAN NOT NULL DEFAULT FALSE,
    totp_secret_enc BYTEA,                    -- optional (J9)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_until    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS email_tokens (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,         -- Argon2id hash of the token
    purpose     TEXT NOT NULL CHECK (purpose IN ('verify_email','login_mfa','recovery')),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS email_tokens_user_idx ON email_tokens (user_id);

CREATE TABLE IF NOT EXISTS login_attempts (
    id          BIGSERIAL PRIMARY KEY,
    email       TEXT,
    ip          TEXT,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    success     BOOLEAN NOT NULL
);
CREATE INDEX IF NOT EXISTS login_attempts_email_ts_idx ON login_attempts (email, ts DESC);
CREATE INDEX IF NOT EXISTS login_attempts_ip_ts_idx ON login_attempts (ip, ts DESC);