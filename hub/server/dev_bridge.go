package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"git.dpnac.cloud/dpnac/central/hub/auth"
)

// -----------------------------------------------------------------------------
// Preview session bridge (DEV ONLY) — URL-token → cookie exchange.
//
// The sandbox preview proxy strips BOTH directions of cookie traffic:
// Set-Cookie from the app never reaches the browser, and Cookie headers from
// the browser never reach the app (verified live: a dev-login through the
// proxy created a session that was never seen again server-side). That is
// sane platform behavior — a preview must not touch platform cookies on the
// shared domain — but it makes the cookie session unusable there.
//
// Bridge design (dev only, gated by DevMode):
//   1. dev-login succeeds server-side → the hub issues a ONE-TIME token bound
//      to the raw session and redirects to hosts?t=<token>.
//   2. hosts.js spots ?t= on load, exchanges it ONCE for the cookie via
//      GET dev/session/redeem?t=… (one-shot, TTL 90 s, then it is purged).
//   3. Even though the proxy strips the resulting Set-Cookie, the exchange
//      also returns the raw session token in the JSON body: the page JS keeps
//      it in localStorage and attaches it as a query param on every API call
//      (?st=<token>). The server accepts ?st= wherever the cookie is absent.
//
// The token lives only in this process's memory (map + mutex), is never
// written to the DB nor to the audit chain, and survives only the redirect.
// If the bridge is unavailable the UI keeps working with the cookie (prod).
// -----------------------------------------------------------------------------

var (
	bridgeMu       sync.Mutex
	bridgeTokens   = map[string]bridgeEntry{} // sha256(token) → entry
	bridgeSessions = map[string]string{}      // sha256(token) → raw session token
)

type bridgeEntry struct{ issued time.Time }

func hashBridge(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// issueBridgeToken binds a fresh one-time token to a raw session token.
func issueBridgeToken(session string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	s := hex.EncodeToString(raw)
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	bridgeTokens[s] = bridgeEntry{issued: time.Now()}
	bridgeSessions[s] = session
	// opportunistic sweep: entries older than 5 minutes are dead anyway.
	for k, e := range bridgeTokens {
		if time.Since(e.issued) > 5*time.Minute {
			delete(bridgeTokens, k)
			delete(bridgeSessions, k)
		}
	}
	return s, nil
}

// redeemBridgeToken consumes the one-time token and returns the bound session.
func redeemBridgeToken(raw string) (string, bool) {
	bridgeMu.Lock()
	defer bridgeMu.Unlock()
	e, ok := bridgeTokens[raw]
	if !ok {
		return "", false
	}
	delete(bridgeTokens, raw)
	if time.Since(e.issued) > 90*time.Second {
		delete(bridgeSessions, raw)
		return "", false
	}
	sess, ok := bridgeSessions[raw]
	if ok {
		delete(bridgeSessions, raw)
	}
	return sess, ok
}

// HandleDevBridgeRedeem exchanges the one-time URL token for the real session
// cookie. One-shot, 90 s TTL. Returns the raw session token in the body so
// the preview UI (whose cookies are stripped by the proxy) can carry it as
// ?st= on subsequent API calls. DevMode gates the whole bridge.
func (s *Server) HandleDevBridgeRedeem(w http.ResponseWriter, r *http.Request) {
	if !s.DevMode {
		apiError(w, http.StatusNotFound, "not found")
		return
	}
	t := r.URL.Query().Get("t")
	sess, ok := redeemBridgeToken(t)
	if t == "" || !ok || auth.SessionUser(s.DB.SQL, sess) == nil {
		apiError(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}
	auth.SetSessionCookie(w, r, sess) // works in prod; stripped by preview proxy
	writeJSON(w, map[string]any{"ok": true, "st": sess})
}
