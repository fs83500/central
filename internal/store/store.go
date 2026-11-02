// Package store wraps the database handle + small helpers.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
)

// DB is a thin wrapper around *sql.DB.
type DB struct {
	SQL *sql.DB
}

// Open connects via the given DSN (env HUB_DATABASE in production).
func Open(dsn string) (*DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return &DB{SQL: db}, nil
}

// QueryRow / Exec / Query are pass-throughs to keep call sites terse.
func (d *DB) QueryRow(query string, args ...any) *sql.Row        { return d.SQL.QueryRow(query, args...) }
func (d *DB) Exec(query string, args ...any) (sql.Result, error) { return d.SQL.Exec(query, args...) }
func (d *DB) Query(query string, args ...any) (*sql.Rows, error) { return d.SQL.Query(query, args...) }

// NewUUID returns a random RFC-4122-ish v4 UUID string.
func NewUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil { //nolint:gosec // uuid gen
		return "00000000-0000-0000-0000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return formatUUID(b)
}

func formatUUID(b []byte) string {
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
