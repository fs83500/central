# Migrations

The canonical SQL now lives in `internal/migrations/sql/hub/` (embedded in
the hub binary via go:embed and applied automatically at boot — beta).

This folder remains for psql-based review workflows:

    psql "$DSN" -f internal/migrations/sql/hub/007_fw_snapshots.sql

The hub applies every file at startup (`HUB_MIGRATIONS=on`, default). All
files are idempotent (IF NOT EXISTS / DROP TRIGGER IF EXISTS guards).
