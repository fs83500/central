// Package server is the hub: enrollment endpoint, agent WebSocket (mTLS),
// REST API for the dashboard. J1 scope: enroll + WS + heartbeat/telemetry/
// inventory storage.
package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"git.dpnac.cloud/dpnac/central/internal/audit"
	"git.dpnac.cloud/dpnac/central/internal/cryptoutil"
	"git.dpnac.cloud/dpnac/central/internal/protocol"
	"git.dpnac.cloud/dpnac/central/internal/store"
	"github.com/gorilla/websocket"
)

// Server holds hub state.
type Server struct {
	DB     *store.DB
	CA     *cryptoutil.InternalCA
	Audit  *audit.PGStore
	Domain string // locked FQDN (SPEC §4.1)
	// quota: max hosts from subscription (pushed by fleet later; default 5)
	Quota int32
	// DevMode: log the MFA code instead of e-mailing it (J2 dev; SMTP in J9).
	DevMode bool
	// MFALogBeta: BETA bridge — until J9 SMTP lands, the one-time login code
	// is written to the hub log so an operator can finish step 2. The env
	// flag HUB_MFA_LOG_BETA=1 makes the exposure explicit; never in GA.
	MFALogBeta bool

	serial atomic.Int64
	// agents: live agent WebSockets (J3 — ping + action delivery).
	agents *agentRegistry
	// siteKey: the site RSA pair (J4, SPEC §6.3) — lazy-loaded, private
	// key never leaves this process except inside its own database.
	siteKey *cryptoutil.SiteKey
}

// logDevMFA prints the login code in dev only (never in production builds
// config: HUB_DEV=1 gate, see cmd/hub).
func (s *Server) logDevMFA(email, code string) {
	if s.DevMode {
		log.Printf("DEV MFA code for %s: %s (SMTP arrives in J9)", email, code)
	}
}

// enrollReq mirrors agent/enroll.Request (token in the BODY).
type enrollReq struct {
	Token string `json:"token"`
	CSR   string `json:"csr"`
	protocol.HostCore
}

type enrollResp struct {
	AgentID   string          `json:"agent_id"`
	Cert      string          `json:"cert"`
	CA        string          `json:"ca"`
	HubConfig json.RawMessage `json:"hub_config"`
}

// HandleEnroll implements PLAN §3.1: verify token (hashed, single use, TTL),
// check quota, sign CSR, create host, audit. Token NEVER appears in logs.
func (s *Server) HandleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.DB == nil {
		apiError(w, http.StatusServiceUnavailable, "HUB_DATABASE not configured")
		return
	}
	var req enrollReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Token check: hash → lookup → single use → TTL.
	tokenHash := hashToken(req.Token)
	var (
		id      int64
		expires time.Time
		usedAt  *time.Time
	)
	err := s.DB.QueryRow(`SELECT id, expires_at, used_at FROM enroll_tokens WHERE token_hash = $1`, tokenHash).Scan(&id, &expires, &usedAt)
	if err != nil {
		s.auditDenied("enroll", "token", "invalid token")
		http.Error(w, "invalid token", http.StatusForbidden)
		return
	}
	if usedAt != nil {
		s.auditDenied("enroll", "token", "token replay")
		http.Error(w, "invalid token", http.StatusForbidden)
		return
	}
	if time.Now().After(expires) {
		s.auditDenied("enroll", "token", "token expired")
		http.Error(w, "invalid token", http.StatusForbidden)
		return
	}

	// Quota check (subscription; default 5 until fleet pushes real one).
	if quota := atomic.LoadInt32(&s.Quota); quota > 0 {
		var count int
		if err := s.DB.QueryRow(`SELECT count(*) FROM hosts WHERE revoked_at IS NULL`).Scan(&count); err == nil && count >= int(quota) {
			s.auditDenied("enroll", "token", fmt.Sprintf("quota %d reached", quota))
			http.Error(w, `{"error":"subscription quota reached"}`, http.StatusPaymentRequired)
			return
		}
	}

	// Attributed agent UUID + sign CSR.
	agentID := store.NewUUID()
	serial := s.serial.Add(1)
	certPEM, err := s.CA.SignAgentCert([]byte(req.CSR), agentID, serial)
	if err != nil {
		s.auditDenied("enroll", agentID, "bad CSR: "+err.Error())
		http.Error(w, "invalid CSR", http.StatusBadRequest)
		return
	}

	// Consume the token atomically (single use even under races).
	res, err := s.DB.Exec(`UPDATE enroll_tokens SET used_at = now(), used_by_host = $1 WHERE id = $2 AND used_at IS NULL`, agentID, id)
	if err != nil || rowsAffected(res) == 0 {
		s.auditDenied("enroll", agentID, "token race")
		http.Error(w, "invalid token", http.StatusForbidden)
		return
	}

	// Create the host row.
	_, err = s.DB.Exec(`
		INSERT INTO hosts (id, hostname, friendly_name, os, os_version, arch,
		                   agent_version, agent_hash, cert_serial, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'offline')`,
		agentID, req.Hostname, req.Hostname, req.OS, req.OSVersion, req.Arch,
		req.AgentVersion, req.AgentHash, fmt.Sprintf("%d", serial))
	if err != nil {
		log.Printf("enroll: insert host: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Audit (N5): enrollment is a sensitive action.
	params, _ := json.Marshal(map[string]string{"hostname": req.Hostname, "os": req.OS, "agent_hash": req.AgentHash})
	if _, err := s.Audit.Append(audit.Event{
		Actor: "agent:" + agentID, ActorType: "agent", Action: "host.enroll",
		TargetType: "host", TargetID: agentID, Result: "ok", Params: params,
	}); err != nil {
		log.Printf("enroll: audit append: %v", err)
	}

	cfg, _ := json.Marshal(map[string]any{
		"heartbeat_s": 30, "telemetry_s": 300, "inventory_s": 86400, "domain": s.Domain,
	})
	writeJSON(w, enrollResp{
		AgentID: agentID, Cert: string(certPEM), CA: string(s.CA.CertPEM), HubConfig: cfg,
	})
}

// HandleWS upgrades an authenticated agent connection (mTLS: client cert
// CN = agent UUID must exist and not be revoked).
var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		return true // agents are not browsers; origin is meaningless here
	},
}

func (s *Server) HandleWS(w http.ResponseWriter, r *http.Request) {
	// mTLS: the reverse proxy (Caddy) terminates TLS; for dev we accept
	// a header set by the proxy after client-cert verification.
	agentID := r.Header.Get("X-Agent-ID")
	if agentID == "" {
		// Dev/CI path: verify client cert from TLS state directly.
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			agentID = r.TLS.PeerCertificates[0].Subject.CommonName
		}
	}
	if agentID == "" {
		http.Error(w, "mTLS required", http.StatusUnauthorized)
		return
	}
	var revoked *time.Time
	var status string
	err := s.DB.QueryRow(`SELECT status, revoked_at FROM hosts WHERE id = $1`, agentID).Scan(&status, &revoked)
	if err != nil {
		http.Error(w, "unknown agent", http.StatusUnauthorized)
		return
	}
	if revoked != nil {
		s.auditDenied("ws", agentID, "revoked cert")
		http.Error(w, "revoked", http.StatusUnauthorized)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer func() { _ = ws.Close() }()

	// Register the live connection (J3: ping + action delivery). The send
	// queue is drained by a writer goroutine — gorilla forbids concurrent
	// writers, and ping/action pushes arrive from HTTP handlers.
	if s.agents == nil {
		s.agents = newRegistry()
	}
	c := s.agents.add(agentID, ws)
	defer s.agents.remove(agentID, c)
	writes := make(chan error, 1)
	go func() {
		for raw := range c.send {
			if err := ws.WriteMessage(websocket.TextMessage, raw); err != nil {
				writes <- err
				return
			}
		}
		writes <- nil
	}()
	defer func() { close(c.send) }()

	log.Printf("ws: agent %s connected from %s", agentID, r.RemoteAddr)
	_, err = s.DB.Exec(`UPDATE hosts SET status = 'online', last_seen = now() WHERE id = $1`, agentID)
	if err != nil {
		log.Printf("ws: mark online: %v", err)
	}

	defer func() {
		_, _ = s.DB.Exec(`UPDATE hosts SET status = 'offline' WHERE id = $1`, agentID)
		log.Printf("ws: agent %s disconnected", agentID)
	}()

	// J3 — deliver queued actions to a freshly (re)connected agent (idea n°2:
	// actions created while offline wait in `pending` and resume here).
	s.deliverPendingActions(agentID, c)

	for {
		var env protocol.Envelope
		if err := ws.ReadJSON(&env); err != nil {
			return
		}
		if err := s.handleAgentMessage(agentID, env); err != nil {
			log.Printf("ws: agent %s: %v", agentID, err)
		}
		_, _ = s.DB.Exec(`UPDATE hosts SET last_seen = now() WHERE id = $1`, agentID)
	}
}

// handleAgentMessage stores heartbeat/telemetry/inventory payloads and
// resolves pongs (J3 RTT) and action results (J3 action queue).
func (s *Server) handleAgentMessage(agentID string, env protocol.Envelope) error {
	switch env.Type {
	case protocol.TypeHeartbeat:
		var hb protocol.Heartbeat
		if err := json.Unmarshal(env.Data, &hb); err != nil {
			return fmt.Errorf("heartbeat decode: %w", err)
		}
		_, err := s.DB.Exec(`
			UPDATE hosts SET agent_version=$1, agent_hash=$2, fw_type=$3,
			                 fw_backend=$4, fw_version=$5, fw_active=$6,
			                 status='online', last_seen=now()
			WHERE id = $7`,
			hb.AgentVersion, hb.AgentHash, hb.FW.Type, hb.FW.Backend,
			hb.FW.Version, hb.FW.Active, agentID)
		return err
	case protocol.TypeTelemetry:
		var t protocol.Telemetry
		if err := json.Unmarshal(env.Data, &t); err != nil {
			return fmt.Errorf("telemetry decode: %w", err)
		}
		disks, _ := json.Marshal(t.Disks)
		net, _ := json.Marshal(t.Net)
		svc, _ := json.Marshal(t.Procs)
		_, err := s.DB.Exec(`
			INSERT INTO telemetry (host_id, cpu_pct, mem_pct, load1, uptime_s, disks, net, services)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			agentID, t.CPU, t.Mem, t.Load1, uptimeOrZero(t), disks, net, svc)
		return err
	case protocol.TypeInventory:
		var inv protocol.Inventory
		if err := json.Unmarshal(env.Data, &inv); err != nil {
			return fmt.Errorf("inventory decode: %w", err)
		}
		// J1: store count only (full storage in J5 with the packages tables).
		params, _ := json.Marshal(map[string]int{"packages": len(inv.Packages), "updates": len(inv.Updates)})
		_, err := s.Audit.Append(audit.Event{
			Actor: "agent:" + agentID, ActorType: "agent", Action: "inventory.report",
			TargetType: "host", TargetID: agentID, Result: "ok", Params: params,
		})
		return err
	case protocol.TypePong:
		// RTT is measured hub-side (SPEC §2.3): sent time is waitPong's,
		// so the pong's own clock never matters (agents stay untrusted).
		var p protocol.Pong
		if err := json.Unmarshal(env.Data, &p); err != nil {
			return fmt.Errorf("pong decode: %w", err)
		}
		resolvePong(p.Ref, time.Since(pongSent(p.Ref)).Milliseconds())
		return nil
	case protocol.TypeActionResult:
		var res protocol.ActionResult
		if err := json.Unmarshal(env.Data, &res); err != nil {
			return fmt.Errorf("action_result decode: %w", err)
		}
		// J4: fw_apply results also close the fw_sessions row.
		s.completeFWSession(agentID, res)
		return s.completeAction(agentID, res)
	case protocol.TypeFWSnapshot:
		// J4: sealed ruleset snapshot (§6.3) — stored opaque.
		var snap protocol.FWSnapshot
		if err := json.Unmarshal(env.Data, &snap); err != nil {
			return fmt.Errorf("fw_snapshot decode: %w", err)
		}
		return s.storeFWSnapshot(agentID, snap)
	default:
		return fmt.Errorf("unknown message type %q", env.Type)
	}
}

// NewEnrollToken generates a raw token, stores its hash with a 24 h TTL and
// returns (raw, hash, error). The raw value is shown ONCE to the operator.
func NewEnrollToken(s *Server, label string) (string, string, error) {
	raw, err := genToken()
	if err != nil {
		return "", "", err
	}
	h := hashToken(raw)
	_, err = s.DB.Exec(`
		INSERT INTO enroll_tokens (token_hash, label, expires_at, created_by)
		VALUES ($1, $2, now() + interval '24 hours', 'dev')`, h, label)
	if err != nil {
		return "", "", err
	}
	return raw, h, nil
}

func genToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "ug-" + hex.EncodeToString(b), nil
}

func (s *Server) auditDenied(action, target, reason string) {
	actor := "unknown"
	if t := strings.SplitN(target, ":", 2); len(t) == 2 {
		actor = "agent:" + t[1]
	}
	_, _ = s.Audit.Append(audit.Event{
		Actor: actor, ActorType: "agent", Action: action + ".denied",
		TargetType: "host", TargetID: target, Result: "denied",
		Params: json.RawMessage(`{"reason":"` + reason + `"}`),
	})
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func rowsAffected(res sqlResult) int64 {
	n, _ := res.RowsAffected()
	return n
}

// sqlResult is the subset of sql.Result we need.
type sqlResult interface {
	RowsAffected() (int64, error)
}

func uptimeOrZero(t protocol.Telemetry) int64 {
	return 0 // Telemetry has no uptime; the heartbeat carries it. Kept for J2.
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ClientTLSConfig is the TLS server config requiring agent client certs
// (used in dev without Caddy; production goes through Caddy client-cert
// verification with pass-through of the verified identity).
func (s *Server) ClientTLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(s.CA.Cert)
	return &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
		MinVersion: tls.VersionTLS12,
	}
}
