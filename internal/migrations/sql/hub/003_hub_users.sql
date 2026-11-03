-- UnifiedGuard — HUB migration 003: local users, sessions, MFA e-mail codes,
-- login rate limiting, theme preference. Auth model = SPEC §4.1:
-- e-mail identity, Argon2id password, double opt-in activation, MFA e-mail
-- (one-time code, TTL 10 min), session cookie HttpOnly+Secure+SameSite=Strict.

CREATE TABLE IF NOT EXISTS hub_users (
    id             BIGSERIAL PRIMARY KEY,
    email          TEXT NOT NULL UNIQUE,
    password_hash  TEXT NOT NULL,                  -- Argon2id encoded string
    display_name   TEXT NOT NULL DEFAULT '',
    role           TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('owner','admin','viewer')),
    is_active      BOOLEAN NOT NULL DEFAULT FALSE,  -- double opt-in required
    activated_at   TIMESTAMPTZ,
    theme          TEXT NOT NULL DEFAULT 'auto' CHECK (theme IN ('auto','light','dark')),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Activation links (double opt-in): hash of the raw token stored, TTL 24 h.
CREATE TABLE IF NOT EXISTS hub_activations (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES hub_users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Sessions: opaque token (hash stored, raw in the cookie), 8 h absolute TTL,
-- 30 min inactivity, rotation on privilege elevation, revoke-all device.
CREATE TABLE IF NOT EXISTS hub_sessions (
    id            BIGSERIAL PRIMARY KEY,
    user_id       BIGINT NOT NULL REFERENCES hub_users(id) ON DELETE CASCADE,
    token_hash    TEXT NOT NULL UNIQUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,
    user_agent    TEXT NOT NULL DEFAULT '',
    revoked_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS hub_sessions_user_idx ON hub_sessions (user_id);

-- MFA e-mail codes (SPEC §4.1.4): one-time, TTL 10 min, hashed storage.
CREATE TABLE IF NOT EXISTS hub_mfa_codes (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES hub_users(id) ON DELETE CASCADE,
    code_hash   TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS hub_mfa_user_idx ON hub_mfa_codes (user_id);

-- Login attempts: per (email, IP) rate limiting. 5 failures → backoff.
CREATE TABLE IF NOT EXISTS hub_login_attempts (
    id          BIGSERIAL PRIMARY KEY,
    email       TEXT NOT NULL,
    ip          TEXT NOT NULL DEFAULT '',
    ok          BOOLEAN NOT NULL,
    at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS hub_login_attempts_idx ON hub_login_attempts (email, ip, at DESC);