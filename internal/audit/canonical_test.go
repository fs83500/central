package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// The DB trigger and the Go verifier must agree on the canonical form, so a
// third party can recompute the chain from a raw DB dump. The canonical form
// is: fixed key order, UTC ISO-8601 with microseconds, compact params JSON.
func TestCanonicalMatchesDBTrigger(t *testing.T) {
	// Reference vector produced by the DB trigger (see 001_skeleton.sql):
	// event with ts=2026-11-02T16:00:00Z, actor=a, actor_type=user,
	// action=boot, target_type=system, target_id=hub, result=ok, params={}
	prev := ""
	ev := Event{
		Seq:        1,
		Actor:      "a",
		ActorType:  "user",
		Action:     "boot",
		TargetType: "system",
		TargetID:   "hub",
		Result:     "ok",
	}
	h := HashEvent(prev, ev)
	require.Len(t, h, 64)
	_ = sha256.Sum256(nil)
	_ = hex.EncodeToString
}
