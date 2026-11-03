-- 007_fw_snapshots.sql — J4: firewall snapshots (SPEC §3.5 commit-confirm
-- + §6.3 site-key envelope encryption).
--
-- The blob is encrypted ON THE AGENT: data key AES-256-GCM, wrapped with the
-- SITE PUBLIC key (RSA-OAEP). The hub stores an opaque blob; only the site
-- private key can open it. Restore flow: the hub unwraps with the site
-- private key ONLY at restore time, server-side, then sends the PLAINTEXT
-- ruleset to the target agent over mTLS. The stored blob stays sealed.
--
-- (The site_keys table already exists — see 001_skeleton: public key only,
-- the private key lives on the hub volume, NEVER in the DB, SPEC §6.3.)
--
-- Sessions: one row per fw_apply action, tracking the commit-confirm state
-- machine: pending_confirm → confirmed | rolled_back | failed.

CREATE TABLE IF NOT EXISTS fw_snapshots (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id       UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    action_id     UUID,                           -- the fw_apply action row (nullable: manual snapshot)
    fw_type       TEXT NOT NULL DEFAULT '',        -- nftables | firewalld | ufw | iptables-legacy
    ciphertext    BYTEA NOT NULL,                  -- AES-256-GCM(snapshot) — opaque
    envelope      JSONB NOT NULL,                 -- {alg:"RSA-OAEP-SHA256", wrapped_key, nonce, site_fp}
    sha256        TEXT NOT NULL,                  -- digest of the plaintext ruleset (verify at restore)
    size_bytes    INT NOT NULL,
    created_by    TEXT NOT NULL DEFAULT '',       -- operator email or "agent:<id>"
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS fw_snapshots_host_idx ON fw_snapshots (host_id, created_at DESC);

-- commit-confirm sessions: the countdown lives on the agent (authoritative —
-- a hub outage must NOT leave a broken ruleset in place), the hub tracks
-- its own view to decide whether to send fw_confirm (heartbeat fresh + probes).
CREATE TABLE IF NOT EXISTS fw_sessions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action_id     UUID REFERENCES actions(id) ON DELETE CASCADE,  -- nullable: the session row is inserted BEFORE the action (race fix: the agent can fail in ms)
    host_id       UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    snapshot_id   UUID REFERENCES fw_snapshots(id),
    ttl_s         INT NOT NULL DEFAULT 300,      -- countdown (default 5 min, operator-set)
    state         TEXT NOT NULL DEFAULT 'pending_confirm', -- pending_confirm | confirmed | rolled_back | failed
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_at    TIMESTAMPTZ,
    confirmed_at  TIMESTAMPTZ,
    rolled_back_at TIMESTAMPTZ,
    deadline      TIMESTAMPTZ,                    -- applied_at + ttl (hub view, agent's own clock rules)
    detail        JSONB NOT NULL DEFAULT '{}'     -- agent's terminal report (rules applied, rollback reason)
);
CREATE INDEX IF NOT EXISTS fw_sessions_state_idx ON fw_sessions (state, deadline);