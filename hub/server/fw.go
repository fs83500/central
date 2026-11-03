// fw.go — J4 hub side: site key + firewall apply/confirm/rollback/snapshots.
//
// The hub NEVER applies rules itself: it ships an fw_apply action to the
// agent (on the socket the agent opened — golden rule) and tracks the
// commit-confirm session. The agent is the countdown authority: even a total
// hub outage leaves the host safe (the agent rolls back on its own timer or
// on connection loss).
//
// Site key (§6.3): one RSA pair per hub. Agents seal snapshots with the
// PUBLIC key; the hub unwraps only at restore/download time, in process.

package server

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"git.dpnac.cloud/dpnac/central/hub/auth"
	"git.dpnac.cloud/dpnac/central/internal/audit"
	"git.dpnac.cloud/dpnac/central/internal/cryptoutil"
	"git.dpnac.cloud/dpnac/central/internal/protocol"
	"git.dpnac.cloud/dpnac/central/internal/store"
)

// SiteKey lazily loads (or creates) the site key pair. SPEC §6.3: the
// PRIVATE key never leaves the centrale — it lives in a key file on the hub
// volume (HUB_SITE_KEY_DIR, default ./data), NEVER in the database. Only the
// public key is registered in site_keys (schema 001: version + BYTEA).
func (s *Server) SiteKey() (*cryptoutil.SiteKey, error) {
	if s.siteKey != nil {
		return s.siteKey, nil
	}
	dir := os.Getenv("HUB_SITE_KEY_DIR")
	if dir == "" {
		dir = "data"
	}
	sk, created, err := cryptoutil.LoadOrCreateSiteKeyFile(dir)
	if err != nil {
		return nil, err
	}
	if created {
		// Register the public key (next version) — private key stays on
		// the hub volume, invisible to the DB and the SaaS.
		var maxVer int
		_ = s.DB.QueryRow(`SELECT COALESCE(MAX(version),0) FROM site_keys`).Scan(&maxVer)
		if _, ierr := s.DB.Exec(
			`INSERT INTO site_keys (version, public_key) VALUES ($1, $2)`,
			maxVer+1, sk.PublicPEM); ierr != nil {
			return nil, ierr
		}
	}
	s.siteKey = sk
	return sk, nil
}

// HandleHostFWApply (POST /api/v1/hosts/{id}/fw/apply) — creates the action
// row + fw_sessions row and queues fw_apply for the agent. The operator
// sends the declarative ruleset + TTL; the hub attaches the site public key.
func (s *Server) HandleHostFWApply(w http.ResponseWriter, r *http.Request) {
	u := auth.FromContext(r.Context())
	if u == nil {
		apiError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	agentID := r.PathValue("id")
	var req struct {
		Rules  []protocol.FWRule `json:"rules"`
		TTLSec int               `json:"ttl_s"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	s.fwApplyFromRequest(w, agentID, req.Rules, req.TTLSec, u)
}

// HandleHostFWConfirm (POST /api/v1/hosts/{id}/fw/confirm) — the operator
// validates the rules. The hub sends fw_confirm on the agent channel ONLY
// if the heartbeat is fresh (the agent's health proxy, §3.5 step 4).
func (s *Server) HandleHostFWConfirm(w http.ResponseWriter, r *http.Request) {
	u := auth.FromContext(r.Context())
	if u == nil {
		apiError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	agentID := r.PathValue("id")
	// session_id may come from the JSON body (POST) or ?session_id= (dev twin).
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		var req struct {
			SessionID string `json:"session_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			sessionID = req.SessionID
		}
	}
	if sessionID == "" {
		_ = s.DB.QueryRow(`
			SELECT id::text FROM fw_sessions
			WHERE host_id = $1 AND state = 'pending_confirm'
			ORDER BY created_at DESC LIMIT 1`, agentID).Scan(&sessionID)
	}
	if sessionID == "" {
		apiError(w, http.StatusConflict, "no pending firewall session on this host")
		return
	}
	// Health gate: heartbeat within 2×30 s (SPEC §3.5 step 4).
	var lastSeen sql.NullTime
	if err := s.DB.QueryRow(`SELECT last_seen FROM hosts WHERE id = $1`, agentID).Scan(&lastSeen); err != nil || !lastSeen.Valid {
		apiError(w, http.StatusConflict, "cannot confirm: host heartbeat is stale")
		return
	}
	if time.Since(lastSeen.Time) > 90*time.Second {
		apiError(w, http.StatusConflict, "cannot confirm: host heartbeat is stale")
		return
	}
	c := s.liveConn(agentID)
	if c == nil {
		apiError(w, http.StatusConflict, "agent is offline — session will roll back at its deadline")
		return
	}
	confirm := protocol.FWConfirm{SessionID: sessionID}
	env := protocol.Envelope{V: protocol.V, ID: newUUID(), Type: protocol.TypeFWConfirm, TS: time.Now().UTC(), Data: mustJSON(confirm)}
	raw, err := json.Marshal(env)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "marshal failed")
		return
	}
	select {
	case c.send <- raw:
	default:
		apiError(w, http.StatusConflict, "agent connection is saturated")
		return
	}
	// The hub records its decision immediately; the agent's terminal
	// report (action_result) will confirm the outcome.
	_, _ = s.DB.Exec(`UPDATE fw_sessions SET state='confirmed', confirmed_at=now() WHERE id = $1`, sessionID)
	params, _ := json.Marshal(map[string]any{"session": sessionID})
	if _, aerr := s.Audit.Append(audit.Event{
		Actor: u.Email, ActorType: "user", Action: "fw.confirm",
		TargetType: "host", TargetID: agentID, Result: "ok", Params: params,
	}); aerr != nil {
		log.Printf("audit: fw.confirm: %v", aerr)
	}
	writeJSON(w, map[string]any{"ok": true, "session_id": sessionID, "state": "confirmed"})
}

// storeFWSnapshot persists the sealed snapshot an agent ships during
// fw_apply (message handler entry point — see server.go).
func (s *Server) storeFWSnapshot(agentID string, snap protocol.FWSnapshot) error {
	// Ownership: the snapshot must reference a fw_session of THIS agent.
	var owner string
	err := s.DB.QueryRow(`
		SELECT fs.host_id::text FROM fw_sessions fs WHERE fs.id = $1`, snap.SessionID).Scan(&owner)
	if err != nil {
		return fmt.Errorf("unknown fw session %s", snap.SessionID)
	}
	if owner != agentID {
		return fmt.Errorf("fw session %s belongs to %s", snap.SessionID, owner)
	}
	envelope, _ := json.Marshal(map[string]any{
		"alg":         "RSA-OAEP-SHA256+AES-256-GCM",
		"wrapped_key": hex.EncodeToString(snap.WrappedKey),
		"nonce":       hex.EncodeToString(snap.Nonce),
		"site_fp":     "",
	})
	_, err = s.DB.Exec(`
		INSERT INTO fw_snapshots (host_id, action_id, fw_type, ciphertext, envelope, sha256, size_bytes, created_by)
		VALUES ($1, NULLIF($2,'')::uuid, $3, $4, $5, $6, $7, $8)`,
		agentID, snap.ActionID, snap.FWType, snap.Ciphertext, envelope, snap.SHA256, snap.SizeBytes, "agent:"+agentID)
	if err != nil {
		return err
	}
	_, _ = s.DB.Exec(`UPDATE fw_sessions SET snapshot_id = (
		SELECT id FROM fw_snapshots WHERE host_id = $1 ORDER BY created_at DESC LIMIT 1
	) WHERE id = $2`, agentID, snap.SessionID)
	params, _ := json.Marshal(map[string]any{"session": snap.SessionID, "size": snap.SizeBytes, "sha256": snap.SHA256})
	if _, aerr := s.Audit.Append(audit.Event{
		Actor: "agent:" + agentID, ActorType: "agent", Action: "fw.snapshot",
		TargetType: "host", TargetID: agentID, Result: "ok", Params: params,
	}); aerr != nil {
		log.Printf("audit: fw.snapshot: %v", aerr)
	}
	return nil
}

// HandleHostFWSnapshots (GET /api/v1/hosts/{id}/fw/snapshots) — list the
// sealed snapshots of a host (metadata only, blobs stay server-side).
func (s *Server) HandleHostFWSnapshots(w http.ResponseWriter, r *http.Request) {
	if auth.FromContext(r.Context()) == nil {
		apiError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	agentID := r.PathValue("id")
	rows, err := s.DB.Query(`
		SELECT id::text, fw_type, sha256, size_bytes, created_by,
		       COALESCE(to_char(created_at,'YYYY-MM-DD HH24:MI:SS'),'')
		FROM fw_snapshots WHERE host_id = $1 ORDER BY created_at DESC LIMIT 50`, agentID)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	type snap struct {
		ID        string `json:"id"`
		FWType    string `json:"fw_type"`
		SHA256    string `json:"sha256"`
		SizeBytes int    `json:"size_bytes"`
		CreatedBy string `json:"created_by"`
		CreatedAt string `json:"created_at"`
	}
	out := []snap{}
	for rows.Next() {
		var x snap
		if err := rows.Scan(&x.ID, &x.FWType, &x.SHA256, &x.SizeBytes, &x.CreatedBy, &x.CreatedAt); err != nil {
			continue
		}
		out = append(out, x)
	}
	writeJSON(w, map[string]any{"snapshots": out})
}

// HandleHostFWSnapshotDownload (GET /api/v1/fw/snapshots/{id}/download) —
// the operator downloads the DECRYPTED snapshot (the hub holds the site
// private key; this is the only path that opens a blob, §6.3 restore rule).
func (s *Server) HandleHostFWSnapshotDownload(w http.ResponseWriter, r *http.Request) {
	u := auth.FromContext(r.Context())
	if u == nil {
		apiError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	id := r.PathValue("id")
	var ct, envJSON []byte
	var sha string
	err := s.DB.QueryRow(`
		SELECT ciphertext, envelope, sha256 FROM fw_snapshots WHERE id = $1`, id).Scan(&ct, &envJSON, &sha)
	if err != nil {
		apiError(w, http.StatusNotFound, "unknown snapshot")
		return
	}
	var env struct {
		WrappedKey string `json:"wrapped_key"`
		Nonce      string `json:"nonce"`
	}
	if err := json.Unmarshal(envJSON, &env); err != nil {
		apiError(w, http.StatusInternalServerError, "bad envelope")
		return
	}
	wrapped, _ := hex.DecodeString(env.WrappedKey)
	nonce, _ := hex.DecodeString(env.Nonce)
	sk, err := s.SiteKey()
	if err != nil {
		apiError(w, http.StatusInternalServerError, "site key unavailable")
		return
	}
	pt, err := sk.UnsealSnapshot(&cryptoutil.SnapshotSeal{
		Ciphertext: ct, Nonce: nonce, WrappedKey: wrapped, SHA256: sha,
	})
	if err != nil {
		apiError(w, http.StatusInternalServerError, "cannot decrypt snapshot: "+err.Error())
		return
	}
	params, _ := json.Marshal(map[string]any{"snapshot": id})
	if _, aerr := s.Audit.Append(audit.Event{
		Actor: u.Email, ActorType: "user", Action: "fw.snapshot.download",
		TargetType: "snapshot", TargetID: id, Result: "ok", Params: params,
	}); aerr != nil {
		log.Printf("audit: fw.snapshot.download: %v", aerr)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="fw-snapshot-`+id[:8]+`.txt"`)
	_, _ = w.Write(pt)
}

// completeFWSession closes the fw_sessions row when the terminal
// action_result of the fw_apply lands (confirmed/rolled_back/failed).
func (s *Server) completeFWSession(agentID string, res protocol.ActionResult) {
	if res.Result == nil {
		return
	}
	var detail struct {
		SessionID string `json:"session_id"`
		Outcome   string `json:"outcome"`
	}
	if err := json.Unmarshal(res.Result, &detail); err != nil || detail.SessionID == "" {
		return
	}
	var owner string
	if err := s.DB.QueryRow(`
		SELECT host_id::text FROM fw_sessions WHERE id = $1`, detail.SessionID).Scan(&owner); err != nil || owner != agentID {
		return
	}
	switch detail.Outcome {
	case "confirmed":
		_, _ = s.DB.Exec(`UPDATE fw_sessions SET state='confirmed', confirmed_at=COALESCE(confirmed_at, now()), detail=$1 WHERE id=$2`, res.Result, detail.SessionID)
	case "rolled_back":
		_, _ = s.DB.Exec(`UPDATE fw_sessions SET state='rolled_back', rolled_back_at=now(), detail=$1 WHERE id=$2`, res.Result, detail.SessionID)
	default:
		_, _ = s.DB.Exec(`UPDATE fw_sessions SET state='failed', detail=$1 WHERE id=$2`, res.Result, detail.SessionID)
	}
}

// HandleHostFWSessions (GET /api/v1/hosts/{id}/fw/sessions) — the UI
// timeline: applied / confirmed / rolled_back sessions of a host.
func (s *Server) HandleHostFWSessions(w http.ResponseWriter, r *http.Request) {
	if auth.FromContext(r.Context()) == nil {
		apiError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	agentID := r.PathValue("id")
	rows, err := s.DB.Query(`
		SELECT id::text, state, ttl_s,
		       COALESCE(to_char(applied_at,'YYYY-MM-DD HH24:MI:SS'),''),
		       COALESCE(to_char(confirmed_at,'YYYY-MM-DD HH24:MI:SS'),''),
		       COALESCE(to_char(rolled_back_at,'YYYY-MM-DD HH24:MI:SS'),''),
		       COALESCE(to_char(deadline,'YYYY-MM-DD HH24:MI:SS'),''),
		       detail::text
		FROM fw_sessions WHERE host_id = $1 ORDER BY created_at DESC LIMIT 50`, agentID)
	if err != nil {
		log.Printf("fw sessions query: %v", err)
		apiError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	type sess struct {
		ID          string          `json:"id"`
		State       string          `json:"state"`
		TTLSec      int             `json:"ttl_s"`
		AppliedAt   string          `json:"applied_at"`
		ConfirmedAt string          `json:"confirmed_at"`
		RolledBack  string          `json:"rolled_back_at"`
		Deadline    string          `json:"deadline"`
		Detail      json.RawMessage `json:"detail"`
	}
	out := []sess{}
	for rows.Next() {
		var x sess
		var detail []byte
		if err := rows.Scan(&x.ID, &x.State, &x.TTLSec, &x.AppliedAt, &x.ConfirmedAt, &x.RolledBack, &x.Deadline, &detail); err != nil {
			continue
		}
		if len(detail) > 0 {
			x.Detail = json.RawMessage(detail)
		}
		out = append(out, x)
	}
	writeJSON(w, map[string]any{"sessions": out})
}

// HandleDevHostFWApply is the dev-only GET twin (preview proxy, GET only).
// Rules travel base64-encoded in ?rules= (JSON array of FWRule).
func (s *Server) HandleDevHostFWApply(w http.ResponseWriter, r *http.Request) {
	if !s.DevMode {
		apiError(w, http.StatusNotFound, "not found")
		return
	}
	u := auth.FromContext(r.Context())
	if u == nil {
		apiError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	agentID := r.PathValue("id")
	enc := r.URL.Query().Get("rules")
	ttl := 0
	if v := r.URL.Query().Get("ttl_s"); v != "" {
		fmt.Sscanf(v, "%d", &ttl)
	}
	if enc == "" {
		apiError(w, http.StatusBadRequest, "missing rules (base64 JSON)")
		return
	}
	rulesJSON, err := base64Decode(enc)
	if err != nil {
		apiError(w, http.StatusBadRequest, "bad base64")
		return
	}
	var rules []protocol.FWRule
	if err := json.Unmarshal(rulesJSON, &rules); err != nil {
		apiError(w, http.StatusBadRequest, "bad rules JSON: "+err.Error())
		return
	}
	s.fwApplyFromRequest(w, agentID, rules, ttl, u)
}

// HandleDevHostFWConfirm is the dev-only GET twin.
func (s *Server) HandleDevHostFWConfirm(w http.ResponseWriter, r *http.Request) {
	if !s.DevMode {
		apiError(w, http.StatusNotFound, "not found")
		return
	}
	s.HandleHostFWConfirm(w, r)
}

// fwApplyFromRequest is the shared body of the POST and dev-GET handlers.
func (s *Server) fwApplyFromRequest(w http.ResponseWriter, agentID string, rules []protocol.FWRule, ttl int, u *auth.User) {
	if len(rules) == 0 {
		apiError(w, http.StatusBadRequest, "no rules given")
		return
	}
	if ttl <= 0 || ttl > 3600 {
		ttl = 300
	}
	var fwType string
	if err := s.DB.QueryRow(`SELECT fw_type FROM hosts WHERE id = $1`, agentID).Scan(&fwType); err != nil {
		apiError(w, http.StatusNotFound, "unknown host")
		return
	}
	if fwType == "" || fwType == "none" {
		apiError(w, http.StatusConflict, "host reports no firewall stack")
		return
	}
	sk, err := s.SiteKey()
	if err != nil {
		apiError(w, http.StatusInternalServerError, "site key unavailable")
		return
	}
	var open int
	_ = s.DB.QueryRow(`SELECT count(*) FROM fw_sessions WHERE host_id = $1 AND state = 'pending_confirm'`, agentID).Scan(&open)
	if open > 0 {
		apiError(w, http.StatusConflict, "a firewall session is already pending confirmation on this host")
		return
	}
	// The session id MUST be inside the action payload: the agent binds
	// the sealed snapshot + the countdown to it (startFWApply rejects
	// payloads without one — a half-formed hub can never brick a host).
	sessionID := newUUID()
	// Insert the session row BEFORE enqueueing: the agent can fail in
	// single-digit milliseconds (missing binary), and completeFWSession
	// must always find its row when the action_result lands.
	_, err = s.DB.Exec(`
		INSERT INTO fw_sessions (id, host_id, ttl_s, state)
		VALUES ($1, $2, $3, 'pending_confirm')`,
		sessionID, agentID, ttl)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "session insert failed")
		return
	}
	payload, _ := json.Marshal(protocol.FWApply{
		SessionID: sessionID, FWType: fwType, TTLSec: ttl, Rules: rules, SitePubKey: string(sk.PublicPEM),
	})
	actionID, err := s.enqueueFWAction(agentID, "fw_apply", payload, u.Email)
	if err != nil {
		_, _ = s.DB.Exec(`DELETE FROM fw_sessions WHERE id = $1`, sessionID)
		apiError(w, http.StatusInternalServerError, "enqueue failed: "+err.Error())
		return
	}
	if _, err := s.DB.Exec(`UPDATE fw_sessions SET action_id = $1 WHERE id = $2`, actionID, sessionID); err != nil {
		apiError(w, http.StatusInternalServerError, "session link failed")
		return
	}
	params, _ := json.Marshal(map[string]any{
		"action": actionID, "session": sessionID, "rules": len(rules), "ttl_s": ttl, "fw_type": fwType,
	})
	if _, aerr := s.Audit.Append(audit.Event{
		Actor: u.Email, ActorType: "user", Action: "fw.apply",
		TargetType: "host", TargetID: agentID, Result: "ok", Params: params,
	}); aerr != nil {
		log.Printf("audit: fw.apply: %v", aerr)
	}
	writeJSON(w, map[string]any{"ok": true, "action_id": actionID, "session_id": sessionID, "ttl_s": ttl})
}

// base64Decode is the query-param decoder for the dev GET twin.
func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func newUUID() string { return store.NewUUID() }

// enqueueFWAction is enqueueAction + immediate delivery attempt (the agent
// must receive the countdown payload while the operator watches).
func (s *Server) enqueueFWAction(hostID, typ string, payload json.RawMessage, createdBy string) (string, error) {
	var id string
	err := s.DB.QueryRow(`
		INSERT INTO actions (host_id, type, payload, status, created_by)
		VALUES ($1, $2, $3, 'pending', $4) RETURNING id::text`,
		hostID, typ, payload, createdBy).Scan(&id)
	if err != nil {
		return "", err
	}
	_, _ = s.DB.Exec(`INSERT INTO action_events (action_id, event) VALUES ($1, 'created')`, id)
	if s.agents != nil {
		if c := s.agents.get(hostID); c != nil {
			s.deliverPendingActions(hostID, c)
		}
	}
	return id, nil
}
