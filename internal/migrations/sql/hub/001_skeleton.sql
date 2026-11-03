CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- UnifiedGuard — HUB migration 001: settings, site keys, audit chain (N5),
-- enrollment tokens, local users, login attempts.
-- Chaining is done by a BEFORE INSERT trigger: hash is computed by the DB
-- itself so the chain can never fork under concurrent appends.

CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS site_keys (
    id          BIGSERIAL PRIMARY KEY,
    version     INT NOT NULL,
    public_key  BYTEA NOT NULL,            -- PUBLIC only; private key lives on
                                            -- the hub volume, never in the DB
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS site_keys_version_idx ON site_keys (version);

-- Audit chain (N5). INSERT-only: no UPDATE, no DELETE are ever issued by the
-- app; the trigger recomputes hash from prev_hash + canonical row so even a
-- direct SQL writer cannot silently tamper.
CREATE TABLE IF NOT EXISTS audit_events (
    seq         BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor       TEXT NOT NULL,
    actor_type  TEXT NOT NULL CHECK (actor_type IN ('user','agent','system')),
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id   TEXT NOT NULL,
    params      JSONB NOT NULL DEFAULT '{}',
    result      TEXT NOT NULL CHECK (result IN ('ok','failed','denied')),
    prev_hash   TEXT NOT NULL DEFAULT '',
    hash        TEXT NOT NULL DEFAULT ''
);

CREATE OR REPLACE FUNCTION ug_audit_hash() RETURNS trigger AS $$
DECLARE
    v_prev TEXT;
    v_canon JSONB;
    v_digest TEXT;
BEGIN
    -- serialize the writer: one append at a time (no chain fork)
    PERFORM pg_advisory_xact_lock(hashtext('ug_audit_chain'));

    -- chain on the LAST inserted row (highest seq), NOT MAX(hash):
    -- MAX() is lexicographic on hex text and can pick an older row when
    -- hashes sort lower, which would fork the chain.
    SELECT COALESCE(
        (SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1), ''
    ) INTO v_prev;

    -- seq is taken from NEW (BIGSERIAL default), so no double-consumption
    v_canon := jsonb_build_object(
        'seq', NEW.seq,
        'ts', to_char(NEW.ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'actor', NEW.actor,
        'actor_type', NEW.actor_type,
        'action', NEW.action,
        'target_type', NEW.target_type,
        'target_id', NEW.target_id,
        'params', NEW.params,
        'result', NEW.result
    );

    v_digest := encode(digest(
        v_prev || v_canon::text,
        'sha256'
    ), 'hex');

    -- the seq was already consumed by v_canon's nextval call; reuse it
    NEW.prev_hash := v_prev;
    NEW.hash := v_digest;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_chain ON audit_events;
CREATE TRIGGER audit_chain BEFORE INSERT ON audit_events
FOR EACH ROW EXECUTE FUNCTION ug_audit_hash();

-- DB-side chain verification: recomputes every hash in order; returns TRUE
-- when the chain is intact. Used by the /audit "verify" endpoint and by tests.
CREATE OR REPLACE FUNCTION ug_audit_verify() RETURNS BOOLEAN AS $$
DECLARE
    v_prev TEXT := '';
    r RECORD;
    v_canon JSONB;
    v_digest TEXT;
BEGIN
    FOR r IN SELECT * FROM audit_events ORDER BY seq LOOP
        IF r.prev_hash <> v_prev THEN
            RETURN FALSE;
        END IF;
        v_canon := jsonb_build_object(
            'seq', r.seq,
            'ts', to_char(r.ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            'actor', r.actor,
            'actor_type', r.actor_type,
            'action', r.action,
            'target_type', r.target_type,
            'target_id', r.target_id,
            'params', r.params,
            'result', r.result
        );
        v_digest := encode(digest(v_prev || v_canon::text, 'sha256'), 'hex');
        IF r.hash <> v_digest THEN
            RETURN FALSE;
        END IF;
        v_prev := r.hash;
    END LOOP;
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;