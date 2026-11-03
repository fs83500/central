package runtime

// fwcommit_test.go — J4 commit-confirm state machine E2E (simulated stacks).
//
// The real firewall backends need CAP_NET_ADMIN, which this sandbox drops:
// the E2E with the actual nftables/ufw/firewalld runs on a target host.
// What we validate here is the full harness: snapshot → seal with the site
// public key → fw_snapshot to the hub → apply → countdown → confirm (rules
// stay) / no confirm (automatic rollback) / disconnect (immediate
// rollback). The seams are the platformSnapshot/Restore/Apply vars.

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	linux "git.dpnac.cloud/dpnac/central/agent/platform/linux"
	"git.dpnac.cloud/dpnac/central/internal/cryptoutil"
	"git.dpnac.cloud/dpnac/central/internal/protocol"
)

type fakeFW struct {
	mu              sync.Mutex
	snapshots       int
	applies         int
	restores        int
	lastSnap        []byte
	restoredContent string
}

func (f *fakeFW) snapshot(string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snapshots++
	return []byte("# baseline ruleset v1"), nil
}

func (f *fakeFW) apply(_ string, _ []linux.FWRuleSpec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies++
	return nil
}

func (f *fakeFW) restore(_ string, snap []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restores++
	f.restoredContent = string(snap) // captured BEFORE the caller zeroes it
	return nil
}

func (f *fakeFW) counts() (int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshots, f.applies, f.restores
}

func installFake(t *testing.T) *fakeFW {
	t.Helper()
	f := &fakeFW{}
	prevS, prevR, prevA := platformSnapshot, platformRestore, platformApply
	platformSnapshot = f.snapshot
	platformRestore = f.restore
	platformApply = f.apply
	t.Cleanup(func() { platformSnapshot, platformRestore, platformApply = prevS, prevR, prevA })
	return f
}

func testSiteKey(t *testing.T) (*cryptoutil.SiteKey, string) {
	t.Helper()
	sk, err := cryptoutil.GenerateSiteKey()
	if err != nil {
		t.Fatal("site key:", err)
	}
	return sk, string(sk.PublicPEM)
}

func applyPayload(t *testing.T, sessionID string, ttl int) protocol.FWApply {
	t.Helper()
	_, pub := testSiteKey(t)
	return protocol.FWApply{
		SessionID: sessionID, FWType: "nftables", TTLSec: ttl,
		Rules: []protocol.FWRule{
			{Direction: "in", Action: "allow", Proto: "tcp", Port: "443", Source: "0.0.0.0/0"},
		},
		SitePubKey: pub,
	}
}

// TestFWConfirmPath — rules stay when fw_confirm lands before the deadline.
func TestFWConfirmPath(t *testing.T) {
	f := installFake(t)
	ap := applyPayload(t, "sess-confirm", 2)
	act := protocol.Action{ID: "act-1", Type: "fw_apply", Payload: mustMarshal(ap)}

	resCh := make(chan *protocol.ActionResult, 1)
	go func() { resCh <- startFWApply(act, ap) }()

	// sealed snapshot must ship to the hub channel
	select {
	case snap := <-sealedForHub:
		if snap.SessionID != "sess-confirm" || snap.FWType != "nftables" || len(snap.Ciphertext) == 0 {
			t.Fatalf("bad snapshot: %+v", snap)
		}
	case <-time.After(time.Second):
		t.Fatal("sealed snapshot never reached the hub channel")
	}
	sn, an, _ := f.counts()
	if sn != 1 || an != 1 {
		t.Fatalf("want 1 snapshot+1 apply, got %d/%d", sn, an)
	}

	// confirm BEFORE the deadline
	if !fwConfirm("sess-confirm") {
		t.Fatal("fwConfirm rejected the live session")
	}
	select {
	case res := <-resCh:
		if res.Status != "done" {
			t.Fatalf("want done, got %s (%s)", res.Status, res.Error)
		}
		var d fwApplyDetail
		_ = json.Unmarshal(res.Result, &d)
		if d.Outcome != "confirmed" {
			t.Fatalf("want outcome confirmed, got %s", d.Outcome)
		}
	case <-time.After(time.Second):
		t.Fatal("startFWApply never returned")
	}
	_, _, rn := f.counts()
	if rn != 0 {
		t.Fatalf("rollback ran on a confirmed session (%d)", rn)
	}
}

// TestFWTimeoutRollsBack — no confirm → automatic rollback at the deadline.
func TestFWTimeoutRollsBack(t *testing.T) {
	f := installFake(t)
	ap := applyPayload(t, "sess-timeout", 1)
	act := protocol.Action{ID: "act-2", Type: "fw_apply", Payload: mustMarshal(ap)}

	resCh := make(chan *protocol.ActionResult, 1)
	go func() { resCh <- startFWApply(act, ap) }()
	<-sealedForHub

	select {
	case res := <-resCh:
		if res.Status != "done" {
			t.Fatalf("want done, got %s", res.Status)
		}
		var d fwApplyDetail
		_ = json.Unmarshal(res.Result, &d)
		if d.Outcome != "rolled_back" {
			t.Fatalf("want outcome rolled_back, got %s", d.Outcome)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("no rollback after TTL — a broken ruleset would stay live")
	}
	_, _, rn := f.counts()
	if rn != 1 {
		t.Fatalf("want exactly 1 restore, got %d", rn)
	}
	f.mu.Lock()
	rc := f.restoredContent
	f.mu.Unlock()
	if rc != "# baseline ruleset v1" {
		t.Fatalf("restored the wrong snapshot: %q", rc)
	}
}

// TestFWSealedSnapshotIsSiteKeyRecoverable — the hub (site private key) can
// decrypt what the agent sealed with the site public key (§6.3 round-trip).
func TestFWSealedSnapshotIsSiteKeyRecoverable(t *testing.T) {
	installFake(t)
	sk, pub := testSiteKey(t)
	ap := protocol.FWApply{
		SessionID: "sess-seal", FWType: "nftables", TTLSec: 30,
		Rules:      []protocol.FWRule{},
		SitePubKey: pub,
	}
	act := protocol.Action{ID: "act-3", Type: "fw_apply", Payload: mustMarshal(ap)}
	go startFWApply(act, ap) //nolint:errcheck // we only need the snapshot

	snap := <-sealedForHub
	pt, err := sk.UnsealSnapshot(&cryptoutil.SnapshotSeal{
		Ciphertext: snap.Ciphertext, Nonce: snap.Nonce,
		WrappedKey: snap.WrappedKey, SHA256: snap.SHA256, SizeBytes: snap.SizeBytes,
	})
	if err != nil {
		t.Fatalf("hub cannot unseal the snapshot: %v", err)
	}
	if string(pt) != "# baseline ruleset v1" {
		t.Fatalf("unsealed ruleset mismatch: %q", string(pt))
	}
	fwConfirm("sess-seal") // close the session cleanly
}

// TestFWRollbackOnDisconnect — the safety net: hub channel lost while
// pending_confirm → immediate rollback, even with hours of TTL left.
func TestFWRollbackOnDisconnect(t *testing.T) {
	f := installFake(t)
	ap := applyPayload(t, "sess-disc", 3600)
	act := protocol.Action{ID: "act-4", Type: "fw_apply", Payload: mustMarshal(ap)}

	resCh := make(chan *protocol.ActionResult, 1)
	go func() { resCh <- startFWApply(act, ap) }()
	<-sealedForHub

	fwRollbackAllOnDisconnect()
	select {
	case res := <-resCh:
		var d fwApplyDetail
		_ = json.Unmarshal(res.Result, &d)
		if d.Outcome != "rolled_back" {
			t.Fatalf("want rolled_back, got %s", d.Outcome)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("disconnect did not roll back")
	}
	if _, _, rn := f.counts(); rn != 1 {
		t.Fatalf("want 1 restore, got %d", rn)
	}
}

// TestFWRejectIncomplete — no session id / no site key → refused before any
// system call (protects against half-formed hub payloads).
func TestFWRejectIncomplete(t *testing.T) {
	f := installFake(t)
	act := protocol.Action{ID: "act-5", Type: "fw_apply", Payload: []byte(`{}`)}
	res := startFWApply(act, protocol.FWApply{})
	if res.Status != "failed" {
		t.Fatalf("want failed, got %s", res.Status)
	}
	sn, an, rn := f.counts()
	if sn+an+rn != 0 {
		t.Fatalf("incomplete payload must not touch the firewall, got %d/%d/%d", sn, an, rn)
	}
}

func mustMarshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
