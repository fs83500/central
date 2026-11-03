package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"git.dpnac.cloud/dpnac/central/hub/auth"
	"git.dpnac.cloud/dpnac/central/internal/audit"
	"git.dpnac.cloud/dpnac/central/internal/protocol"
	"git.dpnac.cloud/dpnac/central/internal/store"
)

// -----------------------------------------------------------------------------
// J3 — Applicative ping (SPEC §2.3, NEVER ICMP) + action queue (idea n°2).
//
// Ping: the hub sends {"type":"ping"} on the WebSocket THE AGENT OPENED and
// measures the round-trip hub-side. RTT lands in hosts.rtt_ms and is shown in
// the dashboard. If the agent is offline the ping answers 409 — the hub
// never dials out to a device (golden rule).
//
// Actions: an operator queues a command (inventory_refresh…) for a host. If
// the host is offline the row waits in `pending`; on reconnection the hub
// delivers every pending action on the agent's own channel, and the agent
// reports action_result which closes the row (done/failed).
// -----------------------------------------------------------------------------

// pongSent tracks when each ping was sent (for hub-side RTT).
var pongSentAt = map[string]time.Time{}

func pongSent(id string) time.Time { return pongSentAt[id] }

// SendPing measures the applicative RTT to a connected agent (ms).
// Timeout d (10 s per PLAN §3.3) → -1, stored as NULL rtt.
func (s *Server) SendPing(agentID string) (int64, error) {
	c := s.liveConn(agentID)
	if c == nil {
		return -1, fmt.Errorf("agent %s is offline", agentID)
	}
	env := protocol.Envelope{V: protocol.V, ID: store.NewUUID(), Type: protocol.TypePing, TS: time.Now().UTC()}
	raw, err := json.Marshal(env)
	if err != nil {
		return -1, err
	}
	pongSentAt[env.ID] = time.Now().UTC()
	select {
	case c.send <- raw:
	default:
		delete(pongSentAt, env.ID)
		return -1, fmt.Errorf("agent %s connection is saturated", agentID)
	}
	rtt := waitPong(env.ID, 10*time.Second)
	delete(pongSentAt, env.ID)
	if rtt < 0 {
		return -1, fmt.Errorf("agent %s did not answer the ping in 10 s", agentID)
	}
	// Persist for the dashboard (hosts.rtt_ms).
	_, _ = s.DB.Exec(`UPDATE hosts SET rtt_ms = $1 WHERE id = $2`, rtt, agentID)
	return rtt, nil
}

// liveConn returns the agent's live connection or nil (offline), lazily
// initializing the registry so tests building Server{} directly keep working.
func (s *Server) liveConn(agentID string) *agentConn {
	if s.agents == nil {
		return nil
	}
	return s.agents.get(agentID)
}

// enqueueAction creates a pending action row (operator-facing). The type is
// validated here so nothing outside the J3 whitelist ever reaches the agent.
func (s *Server) enqueueAction(hostID, typ string, payload json.RawMessage, createdBy string) (string, error) {
	if err := validateActionType(typ); err != nil {
		return "", err
	}
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	var id string
	err := s.DB.QueryRow(`
		INSERT INTO actions (host_id, type, payload, status, created_by)
		VALUES ($1, $2, $3, 'pending', $4) RETURNING id::text`,
		hostID, typ, payload, createdBy).Scan(&id)
	if err != nil {
		return "", err
	}
	_, _ = s.DB.Exec(`INSERT INTO action_events (action_id, event) VALUES ($1, 'created')`, id)
	// Deliver immediately if the host happens to be connected.
	if s.agents != nil {
		if c := s.agents.get(hostID); c != nil {
			s.deliverPendingActions(hostID, c)
		}
	}
	return id, nil
}

// deliverPendingActions pushes every pending action of a host on its live
// connection (used at reconnection AND right after enqueue).
func (s *Server) deliverPendingActions(agentID string, c *agentConn) {
	rows, err := s.DB.Query(`
		SELECT id::text, type, payload FROM actions
		WHERE host_id = $1 AND status = 'pending'
		ORDER BY created_at`, agentID)
	if err != nil {
		log.Printf("actions: list pending %s: %v", agentID, err)
		return
	}
	type pending struct {
		id, typ string
		payload json.RawMessage
	}
	var list []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.typ, &p.payload); err != nil {
			continue
		}
		list = append(list, p)
	}
	_ = rows.Close()
	for _, p := range list {
		env := protocol.Envelope{
			V: protocol.V, ID: store.NewUUID(), Type: protocol.TypeAction, TS: time.Now().UTC(),
			Data: mustJSON(protocol.Action{ID: p.id, Type: p.typ, Payload: p.payload}),
		}
		raw, err := json.Marshal(env)
		if err != nil {
			continue
		}
		select {
		case c.send <- raw:
			_, _ = s.DB.Exec(`UPDATE actions SET status='delivered', delivered_at=now() WHERE id = $1`, p.id)
			_, _ = s.DB.Exec(`INSERT INTO action_events (action_id, event) VALUES ($1, 'delivered')`, p.id)
		default:
			log.Printf("actions: send queue full for %s — action %s stays pending", agentID, p.id)
			return
		}
	}
}

// completeAction stores the agent's terminal answer for an action.
func (s *Server) completeAction(agentID string, res protocol.ActionResult) error {
	// Verify the action belongs to this agent (an agent cannot close
	// another host's action).
	var owner string
	err := s.DB.QueryRow(`SELECT host_id::text FROM actions WHERE id = $1`, res.ID).Scan(&owner)
	if err == sql.ErrNoRows {
		return fmt.Errorf("unknown action %s", res.ID)
	}
	if err != nil {
		return err
	}
	if owner != agentID {
		return fmt.Errorf("action %s belongs to %s, not %s", res.ID, owner, agentID)
	}
	status := res.Status
	if status != "done" && status != "failed" && status != "timeout" {
		return fmt.Errorf("invalid action status %q", status)
	}
	_, err = s.DB.Exec(`
		UPDATE actions SET status=$1, finished_at=now(), result=$2, error=$3 WHERE id = $4`,
		status, res.Result, res.Error, res.ID)
	if err != nil {
		return err
	}
	_, _ = s.DB.Exec(`INSERT INTO action_events (action_id, event) VALUES ($1, $2)`, res.ID, status)
	return nil
}

// HandleHostPing is the dashboard "Ping" button (SPEC §2.3 applicative ping).
func (s *Server) HandleHostPing(w http.ResponseWriter, r *http.Request) {
	u := auth.FromContext(r.Context())
	if u == nil {
		apiError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	agentID := r.PathValue("id")
	var exists bool
	if err := s.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM hosts WHERE id = $1)`, agentID).Scan(&exists); err != nil || !exists {
		apiError(w, http.StatusNotFound, "unknown host")
		return
	}
	rtt, err := s.SendPing(agentID)
	if err != nil {
		apiError(w, http.StatusConflict, err.Error())
		return
	}
	params, _ := json.Marshal(map[string]any{"rtt_ms": rtt})
	if _, aerr := s.Audit.Append(audit.Event{
		Actor: u.Email, ActorType: "user", Action: "host.ping",
		TargetType: "host", TargetID: agentID, Result: "ok",
		Params: params,
	}); aerr != nil {
		log.Printf("audit: host.ping: %v", aerr)
	}
	writeJSON(w, map[string]any{"ok": true, "rtt_ms": rtt})
}

// HandleHostActionCreate queues an action for a host (POST, prod path).
func (s *Server) HandleHostActionCreate(w http.ResponseWriter, r *http.Request) {
	u := auth.FromContext(r.Context())
	if u == nil {
		apiError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	agentID := r.PathValue("id")
	var req struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	switch req.Type {
	case "inventory_refresh", "pkg_list":
		// J3 whitelist — pkg_update/fw_apply arrive with J4/J5.
	default:
		apiError(w, http.StatusBadRequest, "unknown action type "+req.Type)
		return
	}
	if err := validateActionType(req.Type); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Payload) == 0 {
		req.Payload = json.RawMessage(`{}`)
	}
	var exists bool
	if err := s.DB.QueryRow(`SELECT EXISTS(SELECT 1 FROM hosts WHERE id = $1)`, agentID).Scan(&exists); err != nil || !exists {
		apiError(w, http.StatusNotFound, "unknown host")
		return
	}
	id, err := s.enqueueAction(agentID, req.Type, req.Payload, u.Email)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "enqueue failed")
		return
	}
	params, _ := json.Marshal(map[string]any{"action": id, "type": req.Type})
	if _, aerr := s.Audit.Append(audit.Event{
		Actor: u.Email, ActorType: "user", Action: "action.create",
		TargetType: "host", TargetID: agentID, Result: "ok",
		Params: params,
	}); aerr != nil {
		log.Printf("audit: action.create: %v", aerr)
	}
	writeJSON(w, map[string]any{"ok": true, "id": id, "status": "pending"})
}

// HandleHostActions lists a host's actions (newest first, last 50).
func (s *Server) HandleHostActions(w http.ResponseWriter, r *http.Request) {
	if auth.FromContext(r.Context()) == nil {
		apiError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	agentID := r.PathValue("id")
	rows, err := s.DB.Query(`
		SELECT id::text, type, status, created_by,
		       COALESCE(to_char(created_at,'YYYY-MM-DD HH24:MI:SS'),''),
		       COALESCE(to_char(delivered_at,'YYYY-MM-DD HH24:MI:SS'),''),
		       COALESCE(to_char(finished_at,'YYYY-MM-DD HH24:MI:SS'),''),
		       result, error
		FROM actions WHERE host_id = $1 ORDER BY created_at DESC LIMIT 50`, agentID)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	type act struct {
		ID, Type, Status, CreatedBy, CreatedAt, DeliveredAt, FinishedAt, Result, Err string
	}
	out := []act{}
	for rows.Next() {
		var a act
		var result, errText sql.NullString
		if err := rows.Scan(&a.ID, &a.Type, &a.Status, &a.CreatedBy, &a.CreatedAt, &a.DeliveredAt, &a.FinishedAt, &result, &errText); err != nil {
			continue
		}
		a.Result = result.String
		a.Err = errText.String
		out = append(out, a)
	}
	writeJSON(w, map[string]any{"actions": out})
}

// HandleDevHostActionCreate is the dev-only GET twin (preview proxy blocks POST).
func (s *Server) HandleDevHostActionCreate(w http.ResponseWriter, r *http.Request) {
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
	typ := r.URL.Query().Get("type")
	if err := validateActionType(typ); err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	body := struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}{Type: typ}
	id, err := s.enqueueAction(agentID, body.Type, body.Payload, u.Email)
	if err != nil {
		apiError(w, http.StatusBadRequest, "enqueue failed: "+err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "id": id, "status": "pending"})
}

// mustJSON never fails on protocol structs (all marshalable).
func mustJSON(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

// validateActionType enforces the J3 action whitelist (the HTTP gate).
func validateActionType(typ string) error {
	switch typ {
	case "inventory_refresh", "pkg_list":
		return nil
	default:
		return fmt.Errorf("unknown action type %q", typ)
	}
}