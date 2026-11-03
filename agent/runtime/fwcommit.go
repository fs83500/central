// fwcommit.go — J4 commit-confirm harness (SPEC §3.5), agent side.
//
// State machine per fw_apply action:
//
//	1. SNAPSHOT the live ruleset (native dump of the detected stack).
//	2. SEAL it with the SITE PUBLIC key (AES-256-GCM + RSA-OAEP) and send
//	   it to the hub on the same socket (fw_snapshot). The hub stores the
//	   blob opaque — only the site private key can open it.
//	3. APPLY the declarative rules in RUNTIME mode. The agent→hub channel
//	   is force-kept open (the backends always allow the hub management
//	   port first — SPEC §3.5 step 3).
//	4. COUNTDOWN ttl_s starts. The plaintext snapshot lives in memory only:
//	   the agent rolls back EVEN IF THE HUB DIES (hub outage must never
//	   leave a broken ruleset on the host).
//	5. fw_confirm arrives in time → rules stay. Otherwise (deadline,
//	   connection loss) → atomic ROLLBACK of the snapshot.
//	6. Terminal report (confirmed | rolled_back | failed) = action_result.

package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"sync"
	"time"

	platform "git.dpnac.cloud/dpnac/central/agent/platform/linux"
	"git.dpnac.cloud/dpnac/central/internal/cryptoutil"
	"git.dpnac.cloud/dpnac/central/internal/protocol"
)

// fwSession is one live commit-confirm session on this agent.
type fwSession struct {
	mu        sync.Mutex
	sessionID string
	fwType    string
	snapshot  []byte // plaintext, memory-only
	deadline  time.Time
	timer     *time.Timer
	result    *protocol.ActionResult
	done      chan struct{}
}

var (
	fwMu   sync.Mutex
	fwLive = map[string]*fwSession{} // sessionID → live session
)

// fwApplyDetail is the report blob attached to the terminal action_result.
type fwApplyDetail struct {
	SessionID   string `json:"session_id"`
	Outcome     string `json:"outcome"` // confirmed | rolled_back | failed
	RollbackAt  string `json:"rollback_at,omitempty"`
	RollbackErr string `json:"rollback_error,omitempty"`
	SnapshotSHA string `json:"snapshot_sha256,omitempty"`
	SealedSize  int    `json:"sealed_size,omitempty"`
}

// Platform seams: the tests replace these to simulate the stacks — the
// real backends need CAP_NET_ADMIN, which this sandbox drops (E2E with the
// actual nftables/ufw runs on a target host, not in the CI container).
var (
	platformSnapshot = platform.Snapshot
	platformRestore  = platform.Restore
	platformApply    = platform.ApplyRules
)

// startFWApply runs the full §3.5 protocol and BLOCKS until the session is
// resolved (confirm / rollback / failure) — the caller then sends the
// terminal action_result to the hub.
func startFWApply(act protocol.Action, ap protocol.FWApply) *protocol.ActionResult {
	if ap.SessionID == "" || ap.SitePubKey == "" {
		return fwFail(act, ap, "incomplete fw_apply payload")
	}
	// One live session per agent (J4: no parallel applies).
	fwMu.Lock()
	if len(fwLive) > 0 {
		fwMu.Unlock()
		return fwFail(act, ap, "another fw_apply session is already running")
	}
	fwMu.Unlock()

	// 1. Snapshot the LIVE ruleset before touching anything.
	snap, err := platformSnapshot(ap.FWType)
	if err != nil {
		return fwFail(act, ap, "snapshot: "+err.Error())
	}

	// 2. Seal with the site public key (hub will store it opaque).
	seal, err := cryptoutil.SealSnapshot([]byte(ap.SitePubKey), snap)
	if err != nil {
		return fwFail(act, ap, "seal: "+err.Error())
	}

	sess := &fwSession{
		sessionID: ap.SessionID,
		fwType:    ap.FWType,
		snapshot:  snap,
		deadline:  time.Now().Add(time.Duration(ttlOr(ap.TTLSec)) * time.Second),
		done:      make(chan struct{}),
	}
	fwMu.Lock()
	fwLive[ap.SessionID] = sess
	fwMu.Unlock()

	// The sealed snapshot goes to the hub BEFORE the rules are applied (if
	// anything goes wrong, the hub already holds the proof of the before
	// state). Delivery happens through the snapshot channel registered by
	// runOnce — see sendFWSnapshot hook.
	sealedForHub <- protocol.FWSnapshot{
		SessionID:  ap.SessionID,
		ActionID:   act.ID,
		FWType:     ap.FWType,
		Ciphertext: seal.Ciphertext,
		Nonce:      seal.Nonce,
		WrappedKey: seal.WrappedKey,
		SHA256:     seal.SHA256,
		SizeBytes:  seal.SizeBytes,
	}

	// 3. Apply in runtime mode (backends keep the mgmt channel open).
	rules := make([]platform.FWRuleSpec, 0, len(ap.Rules))
	for _, r := range ap.Rules {
		rules = append(rules, platform.FWRuleSpec{
			Direction: r.Direction, Action: r.Action, Proto: r.Proto,
			Port: r.Port, Source: r.Source, Comment: r.Comment,
		})
	}
	if err := platformApply(ap.FWType, rules); err != nil {
		fwRollback(ap.SessionID, "apply failed — restoring snapshot")
		fwCleanup(ap.SessionID)
		// Report the apply failure (rollback already attempted).
		fwMu.Lock()
		delete(fwLive, ap.SessionID)
		fwMu.Unlock()
		return &protocol.ActionResult{
			ID: act.ID, Status: "failed", Error: "apply: " + err.Error(),
			Result: fwDetail(ap.SessionID, "failed"),
		}
	}

	// 4. Countdown → automatic rollback at the deadline.
	sess.mu.Lock()
	sess.timer = time.AfterFunc(time.Until(sess.deadline), func() {
		fwRollback(ap.SessionID, "ttl expired without confirm")
	})
	sess.mu.Unlock()

	// 5. Wait for the resolution.
	select {
	case <-sess.done:
	case <-time.After(time.Until(sess.deadline) + 5*time.Second):
		fwRollback(ap.SessionID, "ttl expired (fallback timer)")
		<-sess.done
	}

	sess.mu.Lock()
	res := sess.result
	sess.mu.Unlock()
	fwCleanup(ap.SessionID)
	if res == nil {
		return fwFail(act, ap, "session ended without a result")
	}
	res.ID = act.ID
	return res
}

// sealedForHub is the channel the runtime loop drains to ship sealed
// snapshots as fw_snapshot envelopes. It is buffered; if it is full the
// apply is aborted (never apply rules whose snapshot was not shipped).
var sealedForHub = make(chan protocol.FWSnapshot, 4)

// fwConfirm marks a session confirmed (hub decision, §3.5 step 4).
func fwConfirm(sessionID string) bool {
	fwMu.Lock()
	sess := fwLive[sessionID]
	fwMu.Unlock()
	if sess == nil {
		return false
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.result != nil {
		return false // already rolled back or failed
	}
	sess.timer.Stop()
	sess.result = &protocol.ActionResult{
		Status: "done",
		Result: fwDetail(sessionID, "confirmed"),
	}
	close(sess.done)
	log.Printf("fw: session %s confirmed — rules stay in place", sessionID)
	return true
}

// fwRollback replays the snapshot atomically (deadline hit or connection
// lost). Idempotent per session.
func fwRollback(sessionID, reason string) {
	fwMu.Lock()
	sess := fwLive[sessionID]
	fwMu.Unlock()
	if sess == nil {
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.result != nil {
		return // already resolved
	}
	var rbErr string
	if err := platformRestore(sess.fwType, sess.snapshot); err != nil {
		rbErr = err.Error()
		log.Printf("fw: session %s ROLLBACK FAILED: %v", sessionID, err)
	} else {
		log.Printf("fw: session %s rolled back (%s)", sessionID, reason)
	}
	status := "done"
	if rbErr != "" {
		status = "failed"
	}
	detail := fwDetail(sessionID, "rolled_back")
	var d fwApplyDetail
	_ = json.Unmarshal(detail, &d)
	d.RollbackAt = time.Now().UTC().Format(time.RFC3339)
	d.RollbackErr = rbErr
	d.SnapshotSHA = sha256Hex(sess.snapshot)
	detail, _ = json.Marshal(d)
	sess.result = &protocol.ActionResult{Status: status, Error: rbErr, Result: detail}
	close(sess.done)
}

// fwRollbackAllOnDisconnect: losing the hub while pending_confirm means the
// rules can never be confirmed → immediate rollback (§3.5 step 5).
func fwRollbackAllOnDisconnect() {
	fwMu.Lock()
	ids := make([]string, 0, len(fwLive))
	for id := range fwLive {
		ids = append(ids, id)
	}
	fwMu.Unlock()
	for _, id := range ids {
		fwRollback(id, "hub connection lost")
	}
}

// fwCleanup removes the session and zeroes the plaintext snapshot.
func fwCleanup(sessionID string) {
	fwMu.Lock()
	sess := fwLive[sessionID]
	delete(fwLive, sessionID)
	fwMu.Unlock()
	if sess != nil {
		sess.mu.Lock()
		for i := range sess.snapshot {
			sess.snapshot[i] = 0
		}
		sess.mu.Unlock()
	}
}

// fwSnapshotPending drains sealed snapshots to the wire (runOnce selects on
// it — see runtime.go).
func fwSnapshotPending() (protocol.FWSnapshot, bool) {
	select {
	case s := <-sealedForHub:
		return s, true
	default:
		return protocol.FWSnapshot{}, false
	}
}

func fwFail(act protocol.Action, ap protocol.FWApply, msg string) *protocol.ActionResult {
	return &protocol.ActionResult{
		ID: act.ID, Status: "failed", Error: msg,
		Result: fwDetail(ap.SessionID, "failed"),
	}
}

func fwDetail(sessionID, outcome string) json.RawMessage {
	raw, _ := json.Marshal(fwApplyDetail{SessionID: sessionID, Outcome: outcome})
	return raw
}

func ttlOr(ttl int) int {
	if ttl <= 0 || ttl > 3600 {
		return 300
	}
	return ttl
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
