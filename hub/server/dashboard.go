// User-facing dashboard API (J2): auth (login + MFA e-mail + logout),
// profile + theme, hosts list/detail, enrollment token creation, audit feed.
// All handlers require a valid session except /auth/*.
package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"git.dpnac.cloud/dpnac/central/hub/auth"
	"git.dpnac.cloud/dpnac/central/internal/audit"
)

// auditUser logs a user-action event into the chained audit (N5).
func (s *Server) auditUser(email, action, result, targetID, params string) {
	if s.Audit == nil {
		return
	}
	_, _ = s.Audit.Append(audit.Event{
		Actor: email, ActorType: "user", Action: action,
		TargetType: "user", TargetID: targetID, Result: result,
		Params: json.RawMessage(params),
	})
}

// userIP honors the Caddy proxy header in dev; prod runs behind Caddy.
func userIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return strings.TrimSpace(strings.Split(v, ",")[0])
	}
	return auth.ClientIP(r)
}

// HandleLogin is step 1 of the SPEC §4.1 flow: e-mail + Argon2id password →
// MFA code e-mailed. 429 when throttled (5 failures → backoff).
func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	ip := userIP(r)

	th := auth.CheckLoginThrottle(s.DB.SQL, req.Email, ip)
	if th.Locked && time.Now().Before(th.RetryAt) {
		s.auditUser(req.Email, "login", "denied", req.Email, `{"reason":"throttled"}`)
		w.Header().Set("Retry-After", "60")
		http.Error(w, `{"error":"too many attempts"}`, http.StatusTooManyRequests)
		return
	}

	var (
		id     int64
		hash   string
		active bool
		role   string
	)
	err := s.DB.QueryRow(`SELECT id, password_hash, is_active, role FROM hub_users WHERE email = $1`, req.Email).
		Scan(&id, &hash, &active, &role)
	if err != nil || !auth.VerifyPassword(hash, req.Password) {
		auth.RecordAttempt(s.DB.SQL, req.Email, ip, false)
		s.auditUser(req.Email, "login", "denied", req.Email, `{"reason":"bad credentials"}`)
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}
	if !active {
		auth.RecordAttempt(s.DB.SQL, req.Email, ip, false)
		s.auditUser(req.Email, "login", "denied", req.Email, `{"reason":"inactive"}`)
		http.Error(w, `{"error":"account not activated"}`, http.StatusUnauthorized)
		return
	}

	auth.RecordAttempt(s.DB.SQL, req.Email, ip, true)
	code, err := auth.IssueMFACode(s.DB.SQL, id)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	// J2: SMTP pluggable (J9); in dev the code is logged and returned.
	if s.DevMode {
		s.logDevMFA(req.Email, code)
	}
	s.auditUser(req.Email, "login.step1", "ok", req.Email, `{}`)
	writeJSON(w, map[string]any{"mfa_required": true})
}

// HandleMFA is step 2: verify the e-mailed code → session cookie.
func (s *Server) HandleMFA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	var id int64
	err := s.DB.QueryRow(`SELECT id FROM hub_users WHERE email = $1 AND is_active = TRUE`, req.Email).Scan(&id)
	if err != nil || !auth.VerifyMFACode(s.DB.SQL, id, req.Code) {
		s.auditUser(req.Email, "login.mfa", "denied", req.Email, `{"reason":"bad code"}`)
		http.Error(w, `{"error":"invalid code"}`, http.StatusUnauthorized)
		return
	}
	raw, err := auth.CreateSession(s.DB.SQL, id, r.UserAgent())
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	auth.SetSessionCookie(w, r, raw)
	s.auditUser(req.Email, "login", "ok", req.Email, `{}`)
	writeJSON(w, map[string]any{"ok": true})
}

// HandleLogout revokes the current session and clears the cookie.
func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.CookieName); err == nil {
		_, _ = s.DB.Exec(`UPDATE hub_sessions SET revoked_at = now() WHERE token_hash = $1`, auth.HashToken(c.Value))
	}
	auth.ClearSessionCookie(s.DB.SQL, w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// HandleMe returns the session user (email, role, theme).
func (s *Server) HandleMe(w http.ResponseWriter, r *http.Request) {
	u := auth.FromContext(r.Context())
	if u == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]any{"email": u.Email, "role": u.Role, "theme": u.Theme})
}

// HandleSetTheme persists the theme choice on the profile (auto/light/dark).
func (s *Server) HandleSetTheme(w http.ResponseWriter, r *http.Request) {
	u := auth.FromContext(r.Context())
	if u == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		Theme string `json:"theme"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	switch req.Theme {
	case "auto", "light", "dark":
	default:
		http.Error(w, `{"error":"invalid theme"}`, http.StatusBadRequest)
		return
	}
	_, err := s.DB.Exec(`UPDATE hub_users SET theme = $1 WHERE id = $2`, req.Theme, u.ID)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "theme": req.Theme})
}

// HandleHosts serves the dashboard host list (derived status window 90 s).
func (s *Server) HandleHosts(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.Query(`
		SELECT id, hostname, os, os_version, fw_type, agent_version, status,
		       COALESCE(to_char(last_seen, 'YYYY-MM-DD HH24:MI:SS'), ''),
		       rtt_ms
		FROM hosts WHERE revoked_at IS NULL
		ORDER BY hostname`)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	defer func() { _ = rows.Close() }()

	type hostRow struct {
		ID           string `json:"id"`
		Hostname     string `json:"hostname"`
		OS           string `json:"os"`
		OSVersion    string `json:"os_version"`
		FWType       string `json:"fw_type"`
		AgentVersion string `json:"agent_version"`
		Status       string `json:"status"`
		LastSeen     string `json:"last_seen"`
		RTTms        *int   `json:"rtt_ms"`
	}
	hosts := []hostRow{}
	for rows.Next() {
		var h hostRow
		if err := rows.Scan(&h.ID, &h.Hostname, &h.OS, &h.OSVersion, &h.FWType, &h.AgentVersion, &h.Status, &h.LastSeen, &h.RTTms); err != nil {
			continue
		}
		// Derived status: online if heartbeat seen in the last 90 s.
		if h.LastSeen != "" {
			if t, err := time.Parse("2006-01-02 15:04:05", h.LastSeen); err == nil {
				if time.Since(t) > 90*time.Second {
					if h.Status == "online" {
						h.Status = "stale"
					}
				}
			}
		}
		hosts = append(hosts, h)
	}
	var used int
	_ = s.DB.QueryRow(`SELECT count(*) FROM hosts WHERE revoked_at IS NULL`).Scan(&used)
	writeJSON(w, map[string]any{
		"domain": s.Domain, "hosts": hosts,
		"quota": s.Quota, "quota_used": used,
	})
}

// HandleHost serves one host with its last telemetry + host audit events.
func (s *Server) HandleHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var (
		hostname, osName, osVer, fwType, agentVer, status, lastSeen string
	)
	var (
		cpu, mem, load *float64
		rtt            *int
	)
	err := s.DB.QueryRow(`
		SELECT hostname, os, os_version, COALESCE(fw_type,''), COALESCE(agent_version,''),
		       status, COALESCE(to_char(last_seen, 'YYYY-MM-DD HH24:MI:SS'), ''), rtt_ms
		FROM hosts WHERE id = $1 AND revoked_at IS NULL`, id).
		Scan(&hostname, &osName, &osVer, &fwType, &agentVer, &status, &lastSeen, &rtt)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	_ = s.DB.QueryRow(`
		SELECT cpu_pct, mem_pct, load1 FROM telemetry
		WHERE host_id = $1 ORDER BY ts DESC LIMIT 1`, id).Scan(&cpu, &mem, &load)

	// 24h telemetry series (sampled ≤ 200 points).
	tRows, err := s.DB.Query(`
		SELECT ts, cpu_pct, mem_pct FROM telemetry
		WHERE host_id = $1 AND ts > now() - interval '24 hours'
		ORDER BY ts`, id)
	if err == nil {
		defer func() { _ = tRows.Close() }()
	}
	type point struct {
		TS  string  `json:"ts"`
		CPU float64 `json:"cpu_pct"`
		Mem float64 `json:"mem_pct"`
	}
	series := []point{}
	if tRows != nil {
		for tRows.Next() {
			var p point
			var ts time.Time
			if err := tRows.Scan(&ts, &p.CPU, &p.Mem); err == nil {
				p.TS = ts.UTC().Format(time.RFC3339)
				series = append(series, p)
			}
		}
	}
	// Sample down to ≤ 200 points for the sparkline.
	if len(series) > 200 {
		step := len(series) / 200
		sampled := make([]point, 0, 200)
		for i := 0; i < len(series); i += step {
			sampled = append(sampled, series[i])
		}
		series = sampled
	}

	// Host audit events (last 50).
	aRows, err := s.DB.Query(`
		SELECT seq, to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'), actor, action, result, hash
		FROM audit_events WHERE target_id = $1 ORDER BY seq DESC LIMIT 50`, id)
	if err == nil {
		defer func() { _ = aRows.Close() }()
	}
	type auditRow struct {
		Seq    int64  `json:"seq"`
		TS     string `json:"ts"`
		Actor  string `json:"actor"`
		Action string `json:"action"`
		Result string `json:"result"`
		Hash   string `json:"hash"`
	}
	events := []auditRow{}
	if aRows != nil {
		for aRows.Next() {
			var a auditRow
			if err := aRows.Scan(&a.Seq, &a.TS, &a.Actor, &a.Action, &a.Result, &a.Hash); err == nil {
				events = append(events, a)
			}
		}
	}

	writeJSON(w, map[string]any{
		"id": id, "domain": s.Domain, "hostname": hostname, "os": osName,
		"os_version": osVer, "fw_type": fwType, "agent_version": agentVer,
		"status": status, "last_seen": lastSeen, "rtt_ms": rtt,
		"cpu_pct": cpu, "mem_pct": mem, "load1": load,
		"telemetry": series, "audit": events,
	})
}

// HandleCreateToken creates an enrollment token from the dashboard (SPEC
// §6.1): raw shown ONCE, hash stored, TTL 24 h, audited (critical action).
func (s *Server) HandleCreateToken(w http.ResponseWriter, r *http.Request) {
	u := auth.FromContext(r.Context())
	if u == nil {
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		Label string `json:"label"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)
	raw, hash, err := NewEnrollToken(s, req.Label)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	params, _ := json.Marshal(map[string]string{"label": req.Label, "token_hash": hash[:16] + "…"})
	_, _ = s.Audit.Append(audit.Event{
		Actor: u.Email, ActorType: "user", Action: "enroll.token.create",
		TargetType: "token", TargetID: hash[:16], Result: "ok", Params: params,
	})
	writeJSON(w, map[string]any{"token": raw})
}

// HandleAuditEvents serves the last 100 audit events (dashboard feed).
func (s *Server) HandleAuditEvents(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.Query(`
		SELECT seq, to_char(ts AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'), actor,
		       action, target_type, target_id, result, hash
		FROM audit_events ORDER BY seq DESC LIMIT 100`)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	defer func() { _ = rows.Close() }()
	type auditRow struct {
		Seq        int64  `json:"seq"`
		TS         string `json:"ts"`
		Actor      string `json:"actor"`
		Action     string `json:"action"`
		TargetType string `json:"target_type"`
		TargetID   string `json:"target_id"`
		Result     string `json:"result"`
		Hash       string `json:"hash"`
	}
	events := []auditRow{}
	for rows.Next() {
		var a auditRow
		if err := rows.Scan(&a.Seq, &a.TS, &a.Actor, &a.Action, &a.TargetType, &a.TargetID, &a.Result, &a.Hash); err == nil {
			events = append(events, a)
		}
	}
	writeJSON(w, map[string]any{"events": events})
}
