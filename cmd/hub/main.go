// Command hub is the UnifiedGuard centrale (self-hosted central server).
// J1: migrations + /api/v1/enroll + agent WebSocket (mTLS) + telemetry
// storage + audit chain. J2: dashboard (login/MFA, hosts, host detail,
// enrollment, audit) + theme light/dark/auto + REST API.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"git.dpnac.cloud/dpnac/central/hub/auth"
	"git.dpnac.cloud/dpnac/central/hub/server"
	"git.dpnac.cloud/dpnac/central/hub/ui"
	"git.dpnac.cloud/dpnac/central/internal/audit"
	"git.dpnac.cloud/dpnac/central/internal/cryptoutil"
	"git.dpnac.cloud/dpnac/central/internal/store"
	"git.dpnac.cloud/dpnac/central/internal/version"
)

func main() {
	addr := getenv("HUB_LISTEN", ":8080")
	dsn := getenv("HUB_DATABASE", "")
	domain := getenv("HUB_DOMAIN", "central.acme.fr")
	dev := os.Getenv("HUB_DEV") == "1"

	// Bootstrap: CA + DB (required for anything beyond /ping).
	var (
		db         *store.DB
		auditStore *audit.PGStore
		ca         *cryptoutil.InternalCA
	)
	if dsn != "" {
		var err error
		if db, err = store.Open(dsn); err != nil {
			log.Fatalf("hub: database: %v", err)
		}
		if auditStore, err = audit.NewPGStore(dsn); err != nil {
			log.Fatalf("hub: audit store: %v", err)
		}
		// The internal CA is persisted on the volume when HUB_CA_DIR is set
		// (dev/demo); in-memory per process otherwise (prod keys volume: J10).
		caDir := getenv("HUB_CA_DIR", "")
		if caDir != "" {
			if ca, err = cryptoutil.LoadOrCreateCA(caDir, "unifiedguard-hub-ca"); err != nil {
				log.Fatalf("hub: CA: %v", err)
			}
		} else if ca, err = cryptoutil.NewInternalCA("unifiedguard-hub-ca", time.Now().UnixNano()); err != nil {
			log.Fatalf("hub: CA: %v", err)
		}
	}

	srvHub := &server.Server{DB: db, CA: ca, Audit: auditStore, Domain: domain, Quota: 5, DevMode: dev}

	// Standalone-TLS mode: trust agent certs signed by the internal CA.
	var clientCAs *x509.CertPool
	if ca != nil {
		clientCAs = x509.NewCertPool()
		clientCAs.AddCert(ca.Cert)
	}

	// Monthly telemetry partitions (migration 005): create current + next
	// month BEFORE serving agents, then keep them rolling every day.
	if db != nil {
		if err := srvHub.EnsureTelemetryPartitions(); err != nil {
			log.Fatalf("hub: telemetry partitions: %v", err)
		}
		go srvHub.RetentionLoop(make(chan struct{}))
	}

	// HUB_DEV_TLS=1: generate a server cert signed by the internal CA and
	// write it to the TLS dir (default /tmp/hub-tls) so the agent mTLS path
	// works without Caddy in dev/review setups.
	if os.Getenv("HUB_DEV_TLS") == "1" && ca != nil {
		if err := writeDevTLSCert(ca, domain); err != nil {
			log.Fatalf("hub: dev tls: %v", err)
		}
	}

	mux := http.NewServeMux()

	// Dev preview helper: the sandbox preview proxy may forward the request
	// with its /preview/<agent>/<port>/ prefix intact. The dashboard UI uses
	// relative paths only, so this middleware simply strips that prefix when
	// present — HUB_UI_PREFIX is empty in production (Caddy strips it).
	uiPrefix := getenv("HUB_UI_PREFIX", "")
	var root http.Handler = mux
	if uiPrefix != "" {
		p := strings.TrimSuffix(uiPrefix, "/")
		root = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, p+"/") {
				r.URL.Path = strings.TrimPrefix(r.URL.Path, p)
			}
			mux.ServeHTTP(w, r)
		})
	}

	mux.HandleFunc("GET /api/v1/ping", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"ok": true, "version": version.String(), "hash": version.SelfHash()})
	})

	// Enrollment (PLAN §3.1): token in the JSON body, never the URL.
	mux.HandleFunc("POST /api/v1/enroll", srvHub.HandleEnroll)
	// Agent WebSocket (the agent initiates — golden rule SPEC §2.1).
	mux.HandleFunc("GET /agent/v1/ws", srvHub.HandleWS)

	// Audit chain verifier (N5) — public read-only integrity proof.
	mux.HandleFunc("GET /api/v1/audit/verify", func(w http.ResponseWriter, r *http.Request) {
		if auditStore == nil {
			writeJSON(w, map[string]any{"ok": false, "error": "HUB_DATABASE not configured"})
			return
		}
		events, err := auditStore.List()
		if err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		var dbOK bool
		if err := auditStore.DB().QueryRow("SELECT ug_audit_verify()").Scan(&dbOK); err == nil && dbOK {
			if err := audit.VerifyChainPG(events); err == nil {
				writeJSON(w, map[string]any{"ok": true, "events": len(events)})
				return
			}
		}
		writeJSON(w, map[string]any{"ok": false, "error": "chain verification failed"})
	})

	// Static assets (CSS + theme.js) and pages.
	mux.Handle("GET /static/", ui.Static())

	// Auth endpoints (no session required).
	mux.HandleFunc("POST /api/v1/auth/login", srvHub.HandleLogin)
	mux.HandleFunc("POST /api/v1/auth/mfa", srvHub.HandleMFA)
	mux.HandleFunc("GET /logout", srvHub.HandleLogout)

	// Session-gated API + pages.
	requireUser := auth.RequireUser(db.SQL, nil)
	gate := func(h http.HandlerFunc) http.Handler { return requireUser(http.HandlerFunc(h)) }

	mux.Handle("GET /api/v1/me", gate(srvHub.HandleMe))
	mux.Handle("PATCH /api/v1/me/theme", gate(srvHub.HandleSetTheme))
	mux.Handle("GET /api/v1/hosts", gate(srvHub.HandleHosts))
	mux.Handle("GET /api/v1/hosts/{id}", gate(srvHub.HandleHost))
	mux.Handle("POST /api/v1/enroll/tokens", gate(srvHub.HandleCreateToken))
	mux.Handle("GET /api/v1/audit/events", gate(srvHub.HandleAuditEvents))

	mux.Handle("GET /login", ui.Page("login.html"))
	mux.Handle("GET /hosts", gate(func(w http.ResponseWriter, r *http.Request) {
		// ?id= → host detail. Query param keeps every page at depth 1 so
		// relative assets/api paths work behind any proxy prefix.
		if id := r.URL.Query().Get("id"); id != "" {
			servePage(w, "host.html")
			return
		}
		servePage(w, "hosts.html")
	}))
	// Legacy deep links /hosts/{id} → hosts?id= (relative redirect keeps
	// any proxy prefix, e.g. the sandbox preview).
	mux.Handle("GET /hosts/{id}", gate(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "../hosts?id="+r.PathValue("id"), http.StatusSeeOther)
	}))
	mux.Handle("GET /enroll", gate(func(w http.ResponseWriter, r *http.Request) {
		servePage(w, "enroll.html")
	}))
	mux.Handle("GET /audit", gate(func(w http.ResponseWriter, r *http.Request) {
		servePage(w, "audit.html")
	}))
	mux.Handle("GET /{$}", gate(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "hosts", http.StatusSeeOther)
	}))

	// Dev-only helper: create an enrollment token (the token is printed ONCE).
	if os.Getenv("HUB_DEV_TOKEN") != "" {
		raw := mustCreateToken(srvHub)
		log.Printf("DEV enrollment token: %s", raw)
	}
	// Dev-only: create the first admin user (double opt-in is replaced by the
	// HUB_DEV=1 bootstrap; production onboarding flow arrives with J9 mail).
	if dev && db != nil {
		email := getenv("HUB_DEV_ADMIN", "admin@dpnac.fr")
		if err := server.BootstrapDevUser(db, email, getenv("HUB_DEV_ADMIN_PASSWORD", "changeme")); err != nil {
			log.Printf("hub: dev admin: %v", err)
		} else {
			log.Printf("DEV admin ready: %s (activate via /login + MFA dev code in logs)", email)
		}
	}

	// HUB_DEV_UI_LISTEN: dev-only second listener for the dashboard (plain
	// HTTP) so the UI is reachable through a sandbox preview proxy while the
	// main listener keeps agent mTLS traffic. NEVER set in production.
	if uiAddr := getenv("HUB_DEV_UI_LISTEN", ""); uiAddr != "" && dev {
		uiSrv := &http.Server{Addr: uiAddr, Handler: root, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			log.Printf("hub: dev UI (HTTP) listening on %s", uiAddr)
			if err := uiSrv.ListenAndServe(); err != http.ErrServerClosed {
				log.Fatal(err)
			}
		}()
	}

	httpSrv := &http.Server{
		Addr: addr, Handler: root, ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("hub %s listening on %s (J2) — domain %s dev=%v", version.String(), addr, domain, dev)
	// Optional TLS (dev/self-signed or behind no reverse proxy): enables the
	// agent mTLS path (wss:// + client cert) that production uses via Caddy.
	if cert, key := os.Getenv("HUB_TLS_CERT"), os.Getenv("HUB_TLS_KEY"); cert != "" && key != "" {
		log.Printf("hub: TLS enabled (cert %s, agent mTLS %v)", cert, clientCAs != nil)
		httpSrv.TLSConfig = tlsConfig(clientCAs)
		if err := httpSrv.ListenAndServeTLS(cert, key); err != http.ErrServerClosed {
			log.Fatal(err)
		}
		return
	}
	if os.Getenv("HUB_DEV_TLS") == "1" {
		log.Printf("hub: TLS enabled (dev cert, agent mTLS)")
		httpSrv.TLSConfig = tlsConfig(clientCAs)
		if err := httpSrv.ListenAndServeTLS(filepath.Join(tlsDir(), "hub.crt"), filepath.Join(tlsDir(), "hub.key")); err != http.ErrServerClosed {
			log.Fatal(err)
		}
		return
	}
	if err := httpSrv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

// tlsConfig enables agent mTLS when the hub runs standalone TLS (no Caddy):
// browsers still work (client certs are REQUESTED, not required) while
// agents present their enrolled certificate directly.
func tlsConfig(clientCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		ClientAuth: tls.RequestClientCert,
		ClientCAs:  clientCAs,
		MinVersion: tls.VersionTLS12,
	}
}

func servePage(w http.ResponseWriter, name string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h := ui.Page(name)
	h.ServeHTTP(w, nil) //nolint:staticcheck // Page is a static byte blob
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// tlsDir is where HUB_DEV_TLS=1 writes the self-signed cert/key.
func tlsDir() string {
	if d := os.Getenv("HUB_TLS_DIR"); d != "" {
		return d
	}
	return "/tmp/hub-tls"
}

// writeDevTLSCert signs a TLS server cert with the hub internal CA: agents
// already trust that CA (returned at enrollment), so wss:// + mTLS works in
// dev without a reverse proxy.
func writeDevTLSCert(ca *cryptoutil.InternalCA, domain string) error {
	dir := tlsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	key, err := cryptoutil.NewAgentKey()
	if err != nil {
		return fmt.Errorf("keygen: %w", err)
	}
	certPEM, err := ca.SignHubCert(key, []string{"localhost", "127.0.0.1", domain}, time.Now().UnixNano())
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPath := filepath.Join(dir, "hub.crt")
	keyPath := filepath.Join(dir, "hub.key")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	log.Printf("hub: dev TLS cert ready: %s (agents trust the hub CA)", certPath)
	return nil
}

func mustCreateToken(s *server.Server) string {
	raw, hash, err := server.NewEnrollToken(s, "dev")
	if err != nil {
		log.Fatalf("hub: token: %v", err)
	}
	_ = hash
	return raw
}
