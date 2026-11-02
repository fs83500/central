package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

// MemStore is an in-memory Store used by tests (and as a reference).
type MemStore struct {
	mu     sync.Mutex
	events []Event
	next   int64
}

func NewMemStore() *MemStore { return &MemStore{next: 1} }

func (m *MemStore) Append(ev Event) (Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev := ""
	if len(m.events) > 0 {
		prev = m.events[len(m.events)-1].Hash
	}
	ev.Seq = m.next
	m.next++
	ev.PrevHash = prev
	ev.Hash = HashEvent(prev, ev)
	m.events = append(m.events, ev)
	return ev, nil
}

func (m *MemStore) List() ([]Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Event, len(m.events))
	copy(out, m.events)
	return out, nil
}

func (m *MemStore) Head() (Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.events) == 0 {
		return Event{}, ErrEmptyChain
	}
	return m.events[len(m.events)-1], nil
}

// --- tests ---

func TestChainHashesCorrectly(t *testing.T) {
	s := NewMemStore()
	e1, err := s.Append(Event{Actor: "admin@acme.fr", ActorType: "user", Action: "boot", TargetType: "system", TargetID: "hub", Result: "ok"})
	require.NoError(t, err)
	e2, err := s.Append(Event{Actor: "agent:uuid1", ActorType: "agent", Action: "host.enroll", TargetType: "host", TargetID: "h1", Result: "ok"})
	require.NoError(t, err)

	assert.Equal(t, "", e1.PrevHash, "genesis has empty prev hash")
	assert.Equal(t, e1.Hash, e2.PrevHash, "second event chains on the first")
	assert.NotEqual(t, e1.Hash, e2.Hash)
}

func TestVerifyChainOK(t *testing.T) {
	s := NewMemStore()
	for i := 0; i < 50; i++ {
		_, err := s.Append(Event{Actor: "a", Action: "x", Result: "ok"})
		require.NoError(t, err)
	}
	events, err := s.List()
	require.NoError(t, err)
	require.NoError(t, VerifyChain(events))
}

func TestVerifyChainDetectsTampering(t *testing.T) {
	s := NewMemStore()
	_, _ = s.Append(Event{Actor: "a", Action: "x", Result: "ok"})
	_, _ = s.Append(Event{Actor: "b", Action: "y", Result: "ok"})
	events, _ := s.List()

	events[1].Result = "denied" // attacker rewrites history
	err := VerifyChain(events)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hash mismatch")
}

func TestVerifyChainDetectsRemoval(t *testing.T) {
	s := NewMemStore()
	for i := 0; i < 5; i++ {
		_, _ = s.Append(Event{Actor: "a", Action: "x", Result: "ok"})
	}
	events, _ := s.List()
	events = events[2:] // attacker deletes the first two records
	err := VerifyChain(events)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "prev_hash")
}

func TestVerifyChainEmpty(t *testing.T) {
	require.NoError(t, VerifyChain(nil))
}

func TestHeadSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	s := NewMemStore()
	ev, err := s.Append(Event{Actor: "a", Action: "x", Result: "ok"})
	require.NoError(t, err)

	sig, err := SignHead(ev, priv)
	require.NoError(t, err)
	assert.True(t, VerifyHeadSignature(ev, pub, sig), "valid signature must verify")

	ev.Hash = "forged"
	assert.False(t, VerifyHeadSignature(ev, pub, sig), "forged head must NOT verify")
	assert.False(t, VerifyHeadSignature(ev, pub, "not-hex"), "garbage signature must fail")
}
