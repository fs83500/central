// Command fleet is the UnifiedGuard global SaaS console
// (global.unifiedguard.cloud). J0 skeleton: /api/v1/ping only.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"git.dpnac.cloud/dpnac/central/internal/version"
)

func main() {
	addr := getenv("FLEET_LISTEN", ":8081")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "version": version.String()})
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("fleet %s listening on %s (skeleton J0)", version.String(), addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
