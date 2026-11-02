// Command hub is the UnifiedGuard centrale (self-hosted central server).
// J1: migrations + /api/v1/enroll (token→CSR→cert) + agent WebSocket (mTLS)
// + heartbeat/telemetry/inventory storage + audit chain endpoints.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"git.dpnac.cloud/dpnac/central/hub/server"
	"git.dpnac.cloud/dpnac/central/internal/audit"
	"git.dpnac.cloud/dpnac/central/internal/cryptoutil"
	"git.dpnac.cloud/dpnac/central/internal/store"
	"git.dpnac.cloud/dpnac/central/internal/version"
)

func main() {
	addr := getenv("HUB_LISTEN", ":8080")
	dsn := getenv("HUB_DATABASE", "")
	domain := getenv("HUB_DOMAIN", "central.acme.fr")

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
		// The internal CA is persisted on the volume; J1 keeps it in-memory
		// per process (prod persistence arrives with the keys volume in J2).
		if ca, err = cryptoutil.NewInternalCA("unifiedguard-hub-ca", time.Now().UnixNano()); err != nil {
			log.Fatalf("hub: CA: %v", err)
		}
	}

	srvHub := &server.Server{DB: db, CA: ca, Audit: auditStore, Domain: domain, Quota: 5}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/ping", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"ok":      true,
			"version": version.String(),
			"hash":    version.SelfHash(),
		})
	})

	// Enrollment (PLAN §3.1): token in the JSON body, never the URL.
	mux.HandleFunc("POST /api/v1/enroll", srvHub.HandleEnroll)
	// Agent WebSocket (the agent initiates — golden rule SPEC §2.1).
	mux.HandleFunc("GET /agent/v1/ws", srvHub.HandleWS)

	// /api/v1/audit/verify — the chain verifier endpoint (N5). Requires the DB.
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

	// Dev-only helper: create an enrollment token (J2 moves this to the
	// dashboard with auth; the token is printed ONCE — only its hash is stored).
	if os.Getenv("HUB_DEV_TOKEN") != "" {
		raw := mustCreateToken(srvHub)
		fmt.Printf("DEV enrollment token: %s\n", raw)
	}

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("hub %s listening on %s (J1)", version.String(), addr)
	if err := httpSrv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
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

func mustCreateToken(s *server.Server) string {
	raw, hash, err := server.NewEnrollToken(s, "dev")
	if err != nil {
		log.Fatalf("hub: token: %v", err)
	}
	_ = hash
	return raw
}
