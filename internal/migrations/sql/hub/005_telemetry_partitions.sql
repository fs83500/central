-- UnifiedGuard — HUB migration 005: monthly-partitioned telemetry.
-- The telemetry table grows fast (1 row/host/5 min = 288 rows/host/day
-- = ~8.6k rows/host/month). PLAN §"Migration 002" required monthly
-- PARTITION BY RANGE from J2: keeps the working set in RAM, retention
-- 90 days becomes a cheap DETACH + DROP instead of a giant DELETE that
-- would bloat the table and hold locks for ages.
--
-- Strategy: migrate the existing plain table to a partitioned one in 3
-- transactional steps: (1) rename the old table, (2) create the new
-- partitioned table, (3) move rows back (backfill), (4) drop the old one.
-- Monthly partitions are created automatically by the hub on boot
-- (EnsureTelemetryPartitions in hub/server) for the current and the next
-- month, so no cron is needed on the central side.

BEGIN;

-- (1) keep the old table aside (index goes with it). Idempotence: skip the
-- whole migration when the table is already partitioned (re-run after a
-- partial failure is safe: step 1 is the only non-idempotent one).
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'telemetry' AND n.nspname = 'public'
          AND c.relkind = 'p'   -- already partitioned
    ) THEN
        RAISE NOTICE 'telemetry already partitioned — skipping 005';
    ELSE
        ALTER TABLE telemetry RENAME TO telemetry_legacy;
    END IF;
END $$;

-- (2) new partitioned table (same shape, plus the partition key)
CREATE TABLE IF NOT EXISTS telemetry (
    host_id   UUID NOT NULL,
    ts        TIMESTAMPTZ NOT NULL DEFAULT now(),
    cpu_pct   REAL NOT NULL,
    mem_pct   REAL NOT NULL,
    load1     REAL NOT NULL,
    uptime_s  BIGINT NOT NULL,
    disks     JSONB NOT NULL DEFAULT '[]',
    net       JSONB NOT NULL DEFAULT '[]',
    services  JSONB NOT NULL DEFAULT '[]',
    PRIMARY KEY (host_id, ts)
) PARTITION BY RANGE (ts);

-- per-host time index (same as J1, now per-partition)
CREATE INDEX IF NOT EXISTS telemetry_host_ts_idx ON telemetry (host_id, ts DESC);

-- (3) backfill: move J1 rows into the partitions.
-- Partitions for past months are created on the fly by the hub on boot;
-- this script only moves rows that fit an existing partition. The hub's
-- EnsureTelemetryPartitions() runs BEFORE any insert, so in practice the
-- migration + first boot cover everything (the backfill below is a
-- best-effort catch-up for the current month).
DO $$
DECLARE
    v_month date := date_trunc('month', now())::date;
    v_name  text := format('telemetry_%s', to_char(v_month, 'YYYY_MM'));
BEGIN
    -- Current-month partition: needed for BOTH the backfill below and the
    -- hub inserts before its first EnsureTelemetryPartitions() call.
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF telemetry FOR VALUES FROM (%L) TO (%L)',
        v_name, v_month, (v_month + interval '1 month')::date);

    IF to_regclass('public.telemetry_legacy') IS NOT NULL THEN
        -- Backfill EVERY past month still in the 90-day retention window
        -- (not just the current one): create one partition per month, move
        -- its rows, and only then drop the legacy table.
        FOR v_month IN
            SELECT DISTINCT date_trunc('month', ts)::date AS m
            FROM telemetry_legacy
            WHERE ts >= date_trunc('month', now() - interval '3 months')::date
            ORDER BY 1
        LOOP
            v_name := format('telemetry_%s', to_char(v_month, 'YYYY_MM'));
            EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I PARTITION OF telemetry FOR VALUES FROM (%L) TO (%L)',
                v_name, v_month, (v_month + interval '1 month')::date);
            EXECUTE format(
                'INSERT INTO telemetry SELECT host_id, ts, cpu_pct, mem_pct, load1, uptime_s, disks, net, services FROM telemetry_legacy WHERE ts >= %L AND ts < %L',
                v_month, (v_month + interval '1 month')::date);
        END LOOP;
        -- Rows older than the 3-month retention window are intentionally
        -- NOT migrated: they leave with the legacy table (retention job).
    END IF;
END $$;

-- (4) drop the legacy table (indexes come along) — only if step 1 renamed it.
-- Still INSIDE the transaction: if the backfill failed, the whole migration
-- rolls back and the legacy table keeps every row (no data loss).
DROP TABLE IF EXISTS telemetry_legacy;

COMMIT;

-- Retention job (pg_cron-free): the hub runs the detach/drop in its daily
-- maintenance loop (J5); the SQL helper below is the single source of truth.
CREATE OR REPLACE FUNCTION ug_telemetry_retention(months INT DEFAULT 3)
RETURNS INT AS $$
DECLARE
    dropped INT := 0;
    v_oldest TIMESTAMPTZ := now() - (months || ' months')::interval;
    r RECORD;
BEGIN
    FOR r IN
        SELECT c.relname AS part
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        JOIN pg_class p ON p.oid = i.inhparent
        WHERE p.relname = 'telemetry'
    LOOP
        -- partition name format telemetry_YYYY_MM
        IF substring(r.part from '([0-9]{4}_[0-9]{2})$') IS NOT NULL
           AND to_date(substring(r.part from '([0-9]{4}_[0-9]{2})$'), 'YYYY_MM') < date_trunc('month', v_oldest)::date
        THEN
            EXECUTE format('DROP TABLE %I', r.part);
            dropped := dropped + 1;
        END IF;
    END LOOP;
    RETURN dropped;
END;
$$ LANGUAGE plpgsql;