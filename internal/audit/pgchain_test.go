package audit

import (
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dsnFlag: PostgreSQL DSN for integration tests. Registered via TestMain so
// `go test ./...` does not break other packages with an unknown flag.
// Usage: go test ./internal/audit -args -audit.dsn "postgres://..."
// or:    UG_TEST_DSN=postgres://... go test ./...
var dsnFlag = flag.String("audit.dsn", os.Getenv("UG_TEST_DSN"), "PostgreSQL DSN for integration tests")

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

// TestPGChainIntegrity runs against a real PostgreSQL (skipped without -audit.dsn
// or UG_TEST_DSN). It verifies the DB trigger chains correctly and that the
// ug_audit_verify() SQL function detects tampering.
func TestPGChainIntegrity(t *testing.T) {
	if *dsnFlag == "" {
		t.Skip("no audit.dsn provided: PG integration test skipped")
	}
	store, err := NewPGStore(*dsnFlag)
	require.NoError(t, err)
	defer func() { _ = store.DB().Close() }()

	// Clean slate for this test only (sequence reset included).
	_, err = store.DB().Exec(`TRUNCATE audit_events RESTART IDENTITY`)
	require.NoError(t, err)

	// Append through the Go store (which INSERTs; the DB trigger hashes).
	e1, err := store.Append(Event{Actor: "admin@acme.fr", ActorType: "user",
		Action: "boot", TargetType: "system", TargetID: "hub", Result: "ok"})
	require.NoError(t, err)
	e2, err := store.Append(Event{Actor: "agent:u1", ActorType: "agent",
		Action: "host.enroll", TargetType: "host", TargetID: "h1", Result: "ok"})
	require.NoError(t, err)

	// The chain must link.
	assert.Equal(t, "", e1.PrevHash)
	assert.Equal(t, e1.Hash, e2.PrevHash)

	// And the in-DB chain must verify with the pure-Go verifier.
	events, err := store.List()
	require.NoError(t, err)
	require.Len(t, events, 2)

	// NOTE: the canonical JSON built by the trigger differs slightly from
	// the Go marshal (key order, timestamp format), so the hashes computed
	// by the DB cannot be re-derived byte-for-byte by HashEvent. The chain
	// INTEGRITY is verified DB-side via a dedicated SQL function (added in
	// the same migration); here we check the Go chain rules that hold
	// regardless of canonical form: linking + monotonic seq.
	assert.Equal(t, "", events[0].PrevHash)
	assert.Equal(t, events[0].Hash, events[1].PrevHash)
	assert.Greater(t, events[1].Seq, events[0].Seq)

	// DB-side verification (SQL function installed by migration 001).
	var ok bool
	require.NoError(t, store.DB().QueryRow(`SELECT ug_audit_verify()`).Scan(&ok))
	assert.True(t, ok, "database-side chain verification must pass")

	// Tamper detection must work DB-side too.
	_, err = store.DB().Exec(`UPDATE audit_events SET result = 'denied' WHERE seq = (SELECT min(seq) FROM audit_events)`)
	require.NoError(t, err, "tampering must be physically possible for the test")
	require.NoError(t, store.DB().QueryRow(`SELECT ug_audit_verify()`).Scan(&ok))
	assert.False(t, ok, "tampered chain must NOT verify")
}
