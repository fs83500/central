-- 004: fix chain fork risk in ug_audit_hash (J2).
-- The trigger chained on MAX(hash) — a TEXT maximum, i.e. LEXICOGRAPHIC.
-- When a new row's hash sorts lower than an older one, the NEXT append
-- re-chained on the older row and forked the chain (verified in practice:
-- seq 3 hashing lower than seq 2 made seq 4 chain back on seq 2).
-- Fix: chain on the row with the highest seq. Fresh installs get the fix
-- via 001; this migration repairs already-deployed databases.
CREATE OR REPLACE FUNCTION ug_audit_hash() RETURNS trigger AS $$
DECLARE
    v_prev TEXT;
    v_canon JSONB;
    v_digest TEXT;
BEGIN
    -- serialize the writer: one append at a time (no chain fork)
    PERFORM pg_advisory_xact_lock(hashtext('ug_audit_chain'));

    -- chain on the LAST inserted row (highest seq), NOT MAX(hash)
    SELECT COALESCE(
        (SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1), ''
    ) INTO v_prev;

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

    NEW.prev_hash := v_prev;
    NEW.hash := v_digest;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
