// Session management + login flow (SPEC §4.1): opaque session token,
// cookie HttpOnly+Secure+SameSite=Strict, hash stored, rotation on login,
// MFA e-mail step mandatory for activated accounts, audit of every login.
package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// CookieName is the hub session cookie.
const CookieName = "ug_session"

// CreateSession inserts a new session and returns the RAW token (goes in the
// cookie; only its SHA-256 is stored).
func CreateSession(db *sql.DB, userID int64, userAgent string) (raw string, err error) {
	raw, err = NewRawToken(32)
	if err != nil {
		return "", err
	}
	_, err = db.Exec(`
		INSERT INTO hub_sessions (user_id, token_hash, expires_at, user_agent)
		VALUES ($1, $2, now() + $3::interval, $4)`,
		userID, HashToken(raw), "8 hours", userAgent)
	if err != nil {
		return "", err
	}
	return raw, nil
}

// SessionUser resolves a raw session token → user, enforcing both TTLs
// (absolute 8 h, inactivity 30 min) and revocation. Returns nil when invalid.
func SessionUser(db *sql.DB, raw string) *User {
	var (
		u       User
		expires time.Time
		last    time.Time
	)
	err := db.QueryRow(`
		SELECT u.id, u.email, u.role, u.is_active, u.theme, s.expires_at, s.last_seen_at
		FROM hub_sessions s JOIN hub_users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.revoked_at IS NULL`,
		HashToken(raw)).Scan(&u.ID, &u.Email, &u.Role, &u.IsActive, &u.Theme, &expires, &last)
	if err != nil {
		return nil
	}
	now := time.Now()
	if now.After(expires) || now.Sub(last) > SessionIdleTTL {
		_, _ = db.Exec(`UPDATE hub_sessions SET revoked_at = now() WHERE token_hash = $1`, HashToken(raw))
		return nil
	}
	_, _ = db.Exec(`UPDATE hub_sessions SET last_seen_at = now() WHERE token_hash = $1`, HashToken(raw))
	return &u
}

// SetSessionCookie writes the session cookie (Strict + HttpOnly + Secure).
func SetSessionCookie(w http.ResponseWriter, r *http.Request, raw string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    raw,
		Path:     "/",
		HttpOnly: true,
		Secure:   isTLS(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(SessionAbsTTL / time.Second),
	})
}

// ClearSessionCookie revokes the session server-side and clears the cookie.
// Under the sandbox preview the caller has no cookie (proxy strips them):
// the session token then arrives as ?st= and is revoked just the same.
func ClearSessionCookie(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	if raw := SessionTokenFromRequest(r); raw != "" {
		_, _ = db.Exec(`UPDATE hub_sessions SET revoked_at = now() WHERE token_hash = $1`, HashToken(raw))
	}
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: isTLS(r), SameSite: http.SameSiteStrictMode,
	})
}

// RevokeAllSessions logs out every device of a user ("expire tout appareil").
func RevokeAllSessions(db *sql.DB, userID int64) {
	_, _ = db.Exec(`UPDATE hub_sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
}

// ClientIP extracts the remote IP (form: r.RemoteAddr → host).
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isTLS: behind Caddy the connection is HTTPS; in dev (plain HTTP) the cookie
// is not marked Secure so the local dashboard still works.
func isTLS(r *http.Request) bool { return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" }

// --- MFA e-mail codes (SPEC §4.1.4) -----------------------------------------

// IssueMFACode generates a 6-digit code, stores its SHA-256 (TTL 10 min),
// "sends" it (SMTP is out of J2 scope: logged in dev, pluggable in J9) and
// returns the raw code so the dev path can display it.
func IssueMFACode(db *sql.DB, userID int64) (raw string, err error) {
	raw, err = NewRawToken(6) // 6 bytes → 8 base64 chars
	if err != nil {
		return "", err
	}
	// 6-digit numeric code (base10 of the random bytes, mod 1e6, padded).
	var n uint64
	for _, b := range []byte(raw)[:4] {
		n = n<<8 | uint64(b)
	}
	code := n % 1000000
	raw = pad6(int(code))
	_, err = db.Exec(`
		INSERT INTO hub_mfa_codes (user_id, code_hash, expires_at)
		VALUES ($1, $2, now() + interval '10 minutes')`,
		userID, HashToken(raw))
	if err != nil {
		return "", err
	}
	return raw, nil
}

func pad6(n int) string {
	s := make([]byte, 6)
	for i := 5; i >= 0; i-- {
		s[i] = byte('0' + n%10)
		n /= 10
	}
	return string(s)
}

// VerifyMFACode consumes a code (single use, TTL enforced by the query).
func VerifyMFACode(db *sql.DB, userID int64, code string) bool {
	res, err := db.Exec(`
		UPDATE hub_mfa_codes SET used_at = now()
		WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL AND expires_at > now()`,
		userID, HashToken(code))
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

// LoginResult is what the login handler responds.
type LoginResult struct {
	NeedMFA bool
	User    *User
}

// Login is the full password step. It does NOT decide the MFA step; the
// caller checks NeedMFA and issues a code.
func Login(db *sql.DB, email, password, ip, userAgent string, audit AuditFn) LoginResult {
	th := CheckLoginThrottle(db, email, ip)
	if th.Locked && time.Now().Before(th.RetryAt) {
		if audit != nil {
			audit("login", email, "throttled", "", "{}")
		}
		return LoginResult{}
	}
	var (
		id     int64
		hash   string
		active bool
	)
	err := db.QueryRow(`SELECT id, password_hash, is_active FROM hub_users WHERE email = $1`, email).
		Scan(&id, &hash, &active)
	if err != nil || !VerifyPassword(hash, password) {
		RecordAttempt(db, email, ip, false)
		if audit != nil {
			audit("login", email, "failed", "", "{}")
		}
		return LoginResult{}
	}
	if !active {
		RecordAttempt(db, email, ip, false)
		if audit != nil {
			audit("login", email, "inactive", "", "{}")
		}
		return LoginResult{}
	}
	RecordAttempt(db, email, ip, true)
	if audit != nil {
		audit("login", email, "ok", "", "{}")
	}
	var u User
	_ = db.QueryRow(`SELECT id, email, role, is_active, theme FROM hub_users WHERE id = $1`, id).
		Scan(&u.ID, &u.Email, &u.Role, &u.IsActive, &u.Theme)
	return LoginResult{User: &u}
}

// AuditFn logs a security event (wired to the chained audit by the caller).
type AuditFn func(action, actor, result, targetID, params string)

// writeJSON is duplicated here to avoid an import cycle with hub/server.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// contextKey avoids collisions in request context.
type contextKey struct{}

// RequireUser wraps a handler requiring a valid session. It stores the user
// in the request context. 401 JSON when not authenticated.
//
// The token comes from the session cookie (prod) OR the ?st= query param.
// The ?st= path exists because the sandbox preview proxy strips cookie
// headers in BOTH directions (Set-Cookie never reaches the browser, Cookie
// never reaches the app): the preview UI exchanges a one-time bridge token
// (dev/session/redeem) and then carries the session as ?st=. It is gated by
// HUB_DEV (acceptSessionParam): never enabled in production.
func RequireUser(db *sql.DB, auditFn AuditFn, acceptSessionParam bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var raw string
			if c, err := r.Cookie(CookieName); err == nil {
				raw = c.Value
			} else if acceptSessionParam {
				raw = r.URL.Query().Get("st")
			}
			if raw == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"error":"unauthenticated"}`)
				return
			}
			u := SessionUser(db, raw)
			if u == nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"error":"invalid session"}`)
				return
			}
			// ?st= is only for the cookie-stripped preview: refresh its cookie
			// counterpart too (no-op when the browser already has it).
			ctx := context.WithValue(r.Context(), contextKey{}, u)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// FromContext returns the authenticated user (nil if absent).
func FromContext(ctx context.Context) *User {
	u, _ := ctx.Value(contextKey{}).(*User)
	return u
}

// SessionTokenFromRequest returns the raw session token presented by the
// request: the cookie (prod) or the ?st= query param (sandbox preview, where
// the proxy strips cookie headers in both directions). Used by logout to
// revoke what the caller actually presents.
func SessionTokenFromRequest(r *http.Request) string {
	if c, err := r.Cookie(CookieName); err == nil {
		return c.Value
	}
	return r.URL.Query().Get("st")
}

// Logf is a small alias so callers can plug their own logger (slog later).
func Logf(format string, args ...any) { log.Printf(format, args...) }
