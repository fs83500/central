// Package audit implements the append-only hash-chained audit log (idea N5).
//
// Each event stores: hash = SHA256(prev_hash || canonical_json(event)).
// The chain head is signed with the hub's Ed25519 key on every append, and
// the head is pushed to the fleet console as a third-party witness.
//
// Rules:
//   - the log is INSERT-only; there is no update, no delete;
//   - VerifyChain walks the whole table and recomputes every hash;
//   - the chain works over any storage implementing Store; PostgreSQL is the
//     production backend, an in-memory one is used by tests.
package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Event is one audit record. PrevHash and Hash chain the records.
type Event struct {
	Seq        int64           `json:"seq"`
	TS         time.Time       `json:"ts"`
	Actor      string          `json:"actor"`       // email, "agent:<uuid>", "system"
	ActorType  string          `json:"actor_type"`  // user | agent | system
	Action     string          `json:"action"`      // "host.enroll", "fw.apply", ...
	TargetType string          `json:"target_type"` // host | action | key | org...
	TargetID   string          `json:"target_id"`
	Params     json.RawMessage `json:"params"`
	Result     string          `json:"result"` // ok | failed | denied
	PrevHash   string          `json:"prev_hash"`
	Hash       string          `json:"hash"`
}

// Store is the persistence contract for the audit log.
type Store interface {
	// Append inserts the event; implementations must set Seq, PrevHash and
	// Hash and return the stored event. Must be safe for concurrent use.
	Append(ev Event) (Event, error)
	// List returns all events ordered by seq.
	List() ([]Event, error)
	// Head returns the last event, or ErrEmptyChain.
	Head() (Event, error)
}

// ErrEmptyChain is returned when the chain has no events yet.
var ErrEmptyChain = fmt.Errorf("audit: empty chain")

// Chain computes the hash of an event given the previous hash.
func HashEvent(prev string, ev Event) string {
	ev.PrevHash = prev
	ev.Hash = "" // never part of its own input
	canonical, _ := json.Marshal(ev)
	sum := sha256.Sum256(append([]byte(prev), canonical...))
	return hex.EncodeToString(sum[:])
}

// VerifyChainPG recomputes every DB-side hash with the independent Go
// implementation (same canonical form as the trigger) and checks the linking.
func VerifyChainPG(events []Event) error {
	prev := ""
	for i, ev := range events {
		if ev.PrevHash != prev {
			return fmt.Errorf("audit: event %d: prev_hash %q, want %q (chain reordered or tampered)", ev.Seq, ev.PrevHash, prev)
		}
		want, err := HashCanonicalPG(prev, ev)
		if err != nil {
			return err
		}
		if ev.Hash != want {
			return fmt.Errorf("audit: event %d: hash mismatch (tampered record)", ev.Seq)
		}
		prev = ev.Hash
		if i > 0 && ev.Seq <= events[i-1].Seq {
			return fmt.Errorf("audit: sequence not increasing at %d", ev.Seq)
		}
	}
	return nil
}

// SignHead signs the current head hash with the given Ed25519 private key.
func SignHead(ev Event, key ed25519.PrivateKey) (string, error) {
	if ev.Hash == "" {
		return "", fmt.Errorf("audit: cannot sign an event without hash")
	}
	sig := ed25519.Sign(key, []byte(ev.Hash))
	return hex.EncodeToString(sig), nil
}

// VerifyHeadSignature checks a head signature.
func VerifyHeadSignature(ev Event, pub ed25519.PublicKey, sigHex string) bool {
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, []byte(ev.Hash), sig)
}

// VerifyChain recomputes every hash and returns the first mismatch.
// An empty chain is valid (nil, nil).
func VerifyChain(events []Event) error {
	prev := ""
	for i, ev := range events {
		want := HashEvent(prev, ev)
		if ev.PrevHash != prev {
			return fmt.Errorf("audit: event %d: prev_hash %q, want %q (chain reordered or tampered)", ev.Seq, ev.PrevHash, prev)
		}
		if ev.Hash != want {
			return fmt.Errorf("audit: event %d: hash mismatch (tampered record)", ev.Seq)
		}
		prev = ev.Hash
		if i > 0 && ev.Seq <= events[i-1].Seq {
			return fmt.Errorf("audit: sequence not increasing at %d", ev.Seq)
		}
	}
	return nil
}
