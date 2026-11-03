-- 006_actions.sql — J3: action queue (idea n°2, PLAN §2 migration 003).
-- An action is created by an operator (or a future campaign) and waits in
-- `pending` until the agent is connected; the hub delivers it on the WS the
-- AGENT opened (golden rule SPEC §2.1 — the hub never dials out). Results
-- arrive as action_result messages and close the row.

CREATE TABLE IF NOT EXISTS actions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id     UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,               -- inventory_refresh | pkg_list | ping | ...
    payload     JSONB NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL DEFAULT 'pending',  -- pending → delivered → running → done/failed/canceled/timeout
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    result      JSONB,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS actions_host_status_idx ON actions (host_id, status);
CREATE INDEX IF NOT EXISTS actions_status_created_idx ON actions (status, created_at);

-- Journal of every step an action goes through (created, delivered, running,
-- done...) — the operator-facing timeline, distinct from the N5 audit chain
-- (which records WHO created WHAT with WHAT intent).
CREATE TABLE IF NOT EXISTS action_events (
    id        BIGSERIAL PRIMARY KEY,
    action_id UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    ts        TIMESTAMPTZ NOT NULL DEFAULT now(),
    event     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS action_events_action_idx ON action_events (action_id, ts);