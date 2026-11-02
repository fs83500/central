package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// PGStore is the PostgreSQL implementation of Store. It relies on a single
// INSERT ... RETURNING inside a transaction with the head locked (advisory or
// SELECT FOR UPDATE on the head) so concurrent appends cannot fork the chain.
type PGStore struct {
	db *sql.DB
}

// NewPGStore opens a PG-backed audit store using the pgx stdlib driver.
// dsn example: postgres://user:pass@host:5432/db?sslmode=disable
func NewPGStore(dsn string) (*PGStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return &PGStore{db: db}, nil
}

// DB exposes the underlying handle (for closing).
func (s *PGStore) DB() *sql.DB { return s.db }

// Append stores an event in the audit_events table and returns it with
// seq, prev_hash and hash filled by the database trigger. The trigger
// guarantees chaining under concurrency (one writer at a time via the
// advisory lock taken in the same transaction).
func (s *PGStore) Append(ev Event) (Event, error) {
	// params: '{}' when the event carries none (DB column is NOT NULL '{}').
	params := []byte(`{}`)
	if len(ev.Params) > 0 {
		if b, err := json.Marshal(ev.Params); err == nil {
			params = b
		}
	}
	// ts: the DB DEFAULT now() is used unless the caller sets a real one.
	// A zero time.Time must NEVER be inserted (it would serialize as
	// 0001-01-01 and diverge from any later re-verification semantics).
	var ts any
	if !ev.TS.IsZero() {
		ts = ev.TS
	}
	row := s.db.QueryRow(`
		INSERT INTO audit_events (ts, actor, actor_type, action,
		                          target_type, target_id, params, result)
		VALUES (COALESCE($1, now()), $2, $3, $4, $5, $6, $7, $8)
		RETURNING seq, ts, prev_hash, hash`,
		ts, ev.Actor, ev.ActorType, ev.Action,
		ev.TargetType, ev.TargetID, params, ev.Result,
	)
	var out Event
	if err := row.Scan(&out.Seq, &out.TS, &out.PrevHash, &out.Hash); err != nil {
		return Event{}, fmt.Errorf("audit: append: %w", err)
	}
	out.Params = params
	out.Actor = ev.Actor
	out.ActorType = ev.ActorType
	out.Action = ev.Action
	out.TargetType = ev.TargetType
	out.TargetID = ev.TargetID
	out.Params = ev.Params
	out.Result = ev.Result
	return out, nil
}

// List returns the full chain, oldest first.
func (s *PGStore) List() ([]Event, error) {
	rows, err := s.db.Query(`
		SELECT seq, ts, actor, actor_type, action, target_type,
		       target_id, COALESCE(params, '{}'::jsonb), result, prev_hash, hash
		FROM audit_events ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Event
	for rows.Next() {
		var ev Event
		if err := rows.Scan(&ev.Seq, &ev.TS, &ev.Actor, &ev.ActorType, &ev.Action,
			&ev.TargetType, &ev.TargetID, &ev.Params, &ev.Result, &ev.PrevHash, &ev.Hash); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// Head returns the last event.
func (s *PGStore) Head() (Event, error) {
	var ev Event
	err := s.db.QueryRow(`
		SELECT seq, ts, actor, actor_type, action, target_type,
		       target_id, params, result, prev_hash, hash
		FROM audit_events ORDER BY seq DESC LIMIT 1`).
		Scan(&ev.Seq, &ev.TS, &ev.Actor, &ev.ActorType, &ev.Action,
			&ev.TargetType, &ev.TargetID, &ev.Params, &ev.Result, &ev.PrevHash, &ev.Hash)
	if errors.Is(err, sql.ErrNoRows) {
		return Event{}, ErrEmptyChain
	}
	if err != nil {
		return Event{}, err
	}
	return ev, nil
}

// VerifyAll walks the whole chain in the database.
func (s *PGStore) VerifyAll(ctx context.Context) error {
	events, err := s.List()
	if err != nil {
		return err
	}
	return VerifyChain(events)
}
