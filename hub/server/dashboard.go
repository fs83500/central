// User-facing dashboard API (J2): auth (login + MFA e-mail + logout),
// profile + theme, hosts list/detail, enrollment token creation, audit feed.
// All handlers require a valid session except /auth/*.
package server

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
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

// apiError writes a JSON API error with the right Content-Type — the old
// http.Error() sent `{"error":…}` bodies as text/plain, which broke strict
// JSON parsing and produced misleading "invalid credentials" UI messages.
func apiError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// HandleLogin is step 1 of the SPEC §4.1 flow: e-mail + Argon2id password →
// MFA code e-mailed. 429 when throttled (5 failures → backoff).
func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		apiError(w, http.StatusServiceUnavailable, "HUB_DATABASE not configured")
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "bad request")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	ip := userIP(r)

	th := auth.CheckLoginThrottle(s.DB.SQL, req.Email, ip)
	if th.Locked && time.Now().Before(th.RetryAt) {
		s.auditUser(req.Email, "login", "denied", req.Email, `{"reason":"throttled"}`)
		w.Header().Set("Retry-After", "60")
		apiError(w, http.StatusTooManyRequests, "too many attempts")
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
		apiError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if !active {
		auth.RecordAttempt(s.DB.SQL, req.Email, ip, false)
		s.auditUser(req.Email, "login", "denied", req.Email, `{"reason":"inactive"}`)
		apiError(w, http.StatusUnauthorized, "account not activated")
		return
	}

	auth.RecordAttempt(s.DB.SQL, req.Email, ip, true)
	code, err := auth.IssueMFACode(s.DB.SQL, id)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// J2: SMTP pluggable (J9); in dev the code is logged and returned so the
	// dashboard is testable without a mail server (NEVER set in production).
	if s.DevMode {
		s.logDevMFA(req.Email, code)
		writeJSON(w, map[string]any{"mfa_required": true, "dev_mfa_code": code})
		return
	}
	// BETA ONLY: outbound SMTP lands with J9. Until then the one-time code
	// is written to the hub log so an operator can complete step 2 — the
	// env flag makes the exposure explicit (refuse to run silently).
	if s.MFALogBeta {
		log.Printf("BETA login code for %s (SMTP arrives with J9): %s", req.Email, code)
	}
	s.auditUser(req.Email, "login.step1", "ok", req.Email, `{}`)
	writeJSON(w, map[string]any{"mfa_required": true})
}

// HandleMFA is step 2: verify the e-mailed code → session cookie.
func (s *Server) HandleMFA(w http.ResponseWriter, r *http.Request) {
	if s.DB == nil {
		apiError(w, http.StatusServiceUnavailable, "HUB_DATABASE not configured")
		return
	}
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "bad request")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	var id int64
	err := s.DB.QueryRow(`SELECT id FROM hub_users WHERE email = $1 AND is_active = TRUE`, req.Email).Scan(&id)
	if err != nil || !auth.VerifyMFACode(s.DB.SQL, id, req.Code) {
		s.auditUser(req.Email, "login.mfa", "denied", req.Email, `{"reason":"bad code"}`)
		apiError(w, http.StatusUnauthorized, "invalid code")
		return
	}
	raw, err := auth.CreateSession(s.DB.SQL, id, r.UserAgent())
	if err != nil {
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}
	auth.SetSessionCookie(w, r, raw)
	s.auditUser(req.Email, "login", "ok", req.Email, `{}`)
	writeJSON(w, map[string]any{"ok": true})
}

// HandleLogout revokes the current session and clears the cookie.
func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	auth.ClearSessionCookie(s.DB.SQL, w, r) // revokes server-side + clears cookie
	http.Redirect(w, r, "login", http.StatusSeeOther)
}

// devLoginError redirects back to login with a machine-readable reason so
// the login page can show WHY the GET fallback failed (never in production).
func devLoginError(w http.ResponseWriter, r *http.Request, reason string) {
	http.Redirect(w, r, "login?err="+url.QueryEscape(reason), http.StatusSeeOther)
}

// HandleDevLogin is a DEV-ONLY single-GET login fallback: the sandbox preview
// proxy only forwards GET/HEAD requests (POST is a 405 at the proxy layer),
// which makes the normal 2-step POST login impossible through that preview.
// DevMode gates it; it performs the full password + dev-MFA flow server-side
// and sets the session cookie. NEVER registered in production builds.
func (s *Server) HandleDevLogin(w http.ResponseWriter, r *http.Request) {
	if !s.DevMode {
		apiError(w, http.StatusNotFound, "not found")
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("email")))
	password := r.URL.Query().Get("password")
	ip := userIP(r)

	th := auth.CheckLoginThrottle(s.DB.SQL, email, ip)
	if th.Locked && time.Now().Before(th.RetryAt) {
		s.auditUser(email, "login", "denied", email, `{"reason":"throttled"}`)
		w.Header().Set("Retry-After", "60")
		devLoginError(w, r, "too many attempts")
		return
	}
	var (
		id     int64
		hash   string
		active bool
	)
	if err := s.DB.QueryRow(`SELECT id, password_hash, is_active FROM hub_users WHERE email = $1`, email).
		Scan(&id, &hash, &active); err != nil || !auth.VerifyPassword(hash, password) {
		auth.RecordAttempt(s.DB.SQL, email, ip, false)
		s.auditUser(email, "login", "denied", email, `{"reason":"bad credentials"}`)
		devLoginError(w, r, "invalid credentials")
		return
	}
	if !active {
		auth.RecordAttempt(s.DB.SQL, email, ip, false)
		s.auditUser(email, "login", "denied", email, `{"reason":"inactive"}`)
		devLoginError(w, r, "account not activated")
		return
	}
	auth.RecordAttempt(s.DB.SQL, email, ip, true)
	code, err := auth.IssueMFACode(s.DB.SQL, id)
	if err != nil {
		devLoginError(w, r, "internal error")
		return
	}
	// The MFA code is verified immediately (DevMode only: the code is logged,
	// not e-mailed — the sandbox preview is a single-operator dev context).
	if !auth.VerifyMFACode(s.DB.SQL, id, code) {
		devLoginError(w, r, "internal error")
		return
	}
	raw, err := auth.CreateSession(s.DB.SQL, id, r.UserAgent())
	if err != nil {
		devLoginError(w, r, "internal error")
		return
	}
	auth.SetSessionCookie(w, r, raw)
	s.auditUser(email, "login", "ok", email, `{"reason":"dev GET login (preview proxy)"}`)
	// Top-level navigation: redirect so the browser lands on the dashboard
	// instead of showing raw JSON. Under the sandbox preview proxy the
	// Set-Cookie above is stripped, so we also bridge the session: a one-time
	// token lets hosts.js redeem it and carry the session as ?st= on API calls
	// (dev only — see dev_bridge.go).
	if s.DevMode {
		if tok, err := issueBridgeToken(raw); err == nil {
			http.Redirect(w, r, "hosts?t="+tok, http.StatusSeeOther)
			return
		}
	}
	http.Redirect(w, r, "hosts", http.StatusSeeOther)
}

// HandleMe returns the session user (email, role, theme).
func (s *Server) HandleMe(w http.ResponseWriter, r *http.Request) {
	u := auth.FromContext(r.Context())
	if u == nil {
		apiError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	writeJSON(w, map[string]any{"email": u.Email, "role": u.Role, "theme": u.Theme})
}

// HandleSetTheme persists the theme choice on the profile (auto/light/dark).
func (s *Server) HandleSetTheme(w http.ResponseWriter, r *http.Request) {
	u := auth.FromContext(r.Context())
	if u == nil {
		apiError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	var req struct {
		Theme string `json:"theme"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "bad request")
		return
	}
	switch req.Theme {
	case "auto", "light", "dark":
	default:
		apiError(w, http.StatusBadRequest, "invalid theme")
		return
	}
	_, err := s.DB.Exec(`UPDATE hub_users SET theme = $1 WHERE id = $2`, req.Theme, u.ID)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, map[string]any{"ok": true, "theme": req.Theme})
}

// HandleDevSetTheme is the GET twin of HandleSetTheme (dev only): the sandbox
// preview proxy forwards GET only, so the theme picker falls back to this
// path behind that proxy. Same validation, same persistence.
func (s *Server) HandleDevSetTheme(w http.ResponseWriter, r *http.Request) {
	if !s.DevMode {
		apiError(w, http.StatusNotFound, "not found")
		return
	}
	u := auth.FromContext(r.Context())
	if u == nil {
		apiError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	theme := r.URL.Query().Get("theme")
	switch theme {
	case "auto", "light", "dark":
	default:
		apiError(w, http.StatusBadRequest, "invalid theme")
		return
	}
	if _, err := s.DB.Exec(`UPDATE hub_users SET theme = $1 WHERE id = $2`, theme, u.ID); err != nil {
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, map[string]any{"ok": true, "theme": theme})
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
		apiError(w, http.StatusInternalServerError, "internal error")
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
// hostPoint is one sampled 24h telemetry point (full snapshot per point).
type hostPoint struct {
	TS     string  `json:"ts"`
	CPU    float64 `json:"cpu_pct"`
	Mem    float64 `json:"mem_pct"`
	Load1  float64 `json:"load1"`
	Uptime int64   `json:"uptime_s"`
	Disks  []any   `json:"disks"`
	Net    []any   `json:"net"`
	Svc    []any   `json:"services"`
}

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
		apiError(w, http.StatusNotFound, "not found")
		return
	}
	_ = s.DB.QueryRow(`
		SELECT cpu_pct, mem_pct, load1 FROM telemetry
		WHERE host_id = $1 ORDER BY ts DESC LIMIT 1`, id).Scan(&cpu, &mem, &load)

	// 24h telemetry series (sampled ≤ 200 points).
	tRows, err := s.DB.Query(`
		SELECT ts, cpu_pct, mem_pct, load1, uptime_s, disks, net, services FROM telemetry
		WHERE host_id = $1 AND ts > now() - interval '24 hours'
		ORDER BY ts`, id)
	if err == nil {
		defer func() { _ = tRows.Close() }()
	}
	series := []hostPoint{}
	if tRows != nil {
		for tRows.Next() {
			var p hostPoint
			var ts time.Time
			var disks, net, svc []byte
			if err := tRows.Scan(&ts, &p.CPU, &p.Mem, &p.Load1, &p.Uptime, &disks, &net, &svc); err == nil {
				p.TS = ts.UTC().Format(time.RFC3339)
				_ = json.Unmarshal(disks, &p.Disks)
				_ = json.Unmarshal(net, &p.Net)
				_ = json.Unmarshal(svc, &p.Svc)
				series = append(series, p)
			}
		}
	}
	// Sample down to ≤ 200 points for the sparkline.
	if len(series) > 200 {
		step := len(series) / 200
		sampled := make([]hostPoint, 0, 200)
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
		// Last full snapshot: disks / network / services (finition J2).
		"disks":    lastDisks(series),
		"net":      lastNet(series),
		"services": lastServices(series),
		"uptime_s": lastUptime(series),
	})
}

// lastDisks returns the last non-empty disks snapshot (newest first).
func lastDisks(series []hostPoint) []any {
	for i := len(series) - 1; i >= 0; i-- {
		if len(series[i].Disks) > 0 {
			return series[i].Disks
		}
	}
	return []any{}
}

// lastNet returns the last non-empty network snapshot (newest first).
func lastNet(series []hostPoint) []any {
	for i := len(series) - 1; i >= 0; i-- {
		if len(series[i].Net) > 0 {
			return series[i].Net
		}
	}
	return []any{}
}

// lastServices returns the last non-empty services snapshot (newest first).
func lastServices(series []hostPoint) []any {
	for i := len(series) - 1; i >= 0; i-- {
		if len(series[i].Svc) > 0 {
			return series[i].Svc
		}
	}
	return []any{}
}

// lastUptime returns the uptime of the newest point (0 when no telemetry).
func lastUptime(series []hostPoint) int64 {
	if len(series) == 0 {
		return 0
	}
	return series[len(series)-1].Uptime
}

// HandleCreateToken creates an enrollment token from the dashboard (SPEC
// §6.1): raw shown ONCE, hash stored, TTL 24 h, audited (critical action).
func (s *Server) HandleCreateToken(w http.ResponseWriter, r *http.Request) {
	u := auth.FromContext(r.Context())
	if u == nil {
		apiError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	var req struct {
		Label string `json:"label"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)
	raw, hash, err := NewEnrollToken(s, req.Label)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "internal error")
		return
	}
	params, _ := json.Marshal(map[string]string{"label": req.Label, "token_hash": hash[:16] + "…"})
	_, _ = s.Audit.Append(audit.Event{
		Actor: u.Email, ActorType: "user", Action: "enroll.token.create",
		TargetType: "token", TargetID: hash[:16], Result: "ok", Params: params,
	})
	writeJSON(w, map[string]any{"token": raw})
}

// HandleDevCreateToken is the GET twin of HandleCreateToken (dev only): the
// sandbox preview proxy forwards GET only, so token creation from the enroll
// page falls back to this path behind that proxy. Same auth, audit and rules.
func (s *Server) HandleDevCreateToken(w http.ResponseWriter, r *http.Request) {
	if !s.DevMode {
		apiError(w, http.StatusNotFound, "not found")
		return
	}
	u := auth.FromContext(r.Context())
	if u == nil {
		apiError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	req := struct{ Label string }{Label: r.URL.Query().Get("label")}
	raw, hash, err := NewEnrollToken(s, req.Label)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "internal error")
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
		apiError(w, http.StatusInternalServerError, "internal error")
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
