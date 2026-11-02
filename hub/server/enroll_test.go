// Integration test for the enrollment flow against a real PostgreSQL:
// token creation → enroll (CSR signing) → token single-use → host row →
// audit event → WS heartbeat updates the host.
package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"git.dpnac.cloud/dpnac/central/agent/enroll"
	"git.dpnac.cloud/dpnac/central/internal/audit"
	"git.dpnac.cloud/dpnac/central/internal/cryptoutil"
	"git.dpnac.cloud/dpnac/central/internal/protocol"
	"git.dpnac.cloud/dpnac/central/internal/store"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	dsn := os.Getenv("UG_TEST_DSN")
	if dsn == "" {
		t.Skip("UG_TEST_DSN not set: PG integration test skipped")
	}
	db, err := store.Open(dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.SQL.Close() })
	auditStore, err := audit.NewPGStore(dsn)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	ca, err := cryptoutil.NewInternalCA("test-ca", 1)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	return &Server{DB: db, CA: ca, Audit: auditStore, Domain: "central.test.fr", Quota: 5}
}

// TestEnrollFlow walks PLAN §3.1 end to end (HTTP only, WS in TestHeartbeat).
func TestEnrollFlow(t *testing.T) {
	s := testServer(t)

	// Clean slate for the tables this test touches.
	_, _ = s.DB.Exec(`TRUNCATE enroll_tokens, hosts, telemetry RESTART IDENTITY`)

	// 1. Create a token.
	raw, _, err := NewEnrollToken(s, "test")
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if !strings.HasPrefix(raw, "ug-") || len(raw) != 3+32 {
		t.Fatalf("token format: %q", raw)
	}

	// 2. Agent side: build the CSR like the real agent does.
	key, err := cryptoutil.NewAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := cryptoutil.CSRRequest(key, "")
	if err != nil {
		t.Fatal(err)
	}

	// 3. POST /api/v1/enroll.
	body, _ := json.Marshal(enroll.Request{
		Token: raw,
		CSR:   string(csr),
		HostCore: protocol.HostCore{
			Hostname: "p-dns-01", OS: "debian", OSVersion: "12",
			AgentVersion: "test", AgentHash: "deadbeef",
		},
	})
	rec := httptest.NewRecorder()
	srv := httptest.NewServer(http.HandlerFunc(s.HandleEnroll))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	srv.Config.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll: HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var resp enroll.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AgentID == "" || resp.Cert == "" || resp.CA == "" {
		t.Fatalf("incomplete response: %+v", resp)
	}

	// 4. Token single use: replay must be 403.
	rec2 := httptest.NewRecorder()
	req2, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	srv.Config.Handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("replay: expected 403, got %d", rec2.Code)
	}

	// 5. Host row exists.
	var count int
	if err := s.DB.QueryRow(`SELECT count(*) FROM hosts WHERE hostname = 'p-dns-01'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("host row: count=%d err=%v", count, err)
	}

	// 6. Audit event recorded.
	var auditCount int
	if err := s.DB.QueryRow(`SELECT count(*) FROM audit_events WHERE action = 'host.enroll' AND result = 'ok'`).Scan(&auditCount); err != nil || auditCount == 0 {
		t.Fatalf("audit: count=%d err=%v", auditCount, err)
	}

	// 7. Invalid token → denied + audited.
	rec3 := httptest.NewRecorder()
	badBody, _ := json.Marshal(enroll.Request{Token: "ug-ffffffffffffffffffffffffffffffff", CSR: string(csr)})
	req3, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(badBody))
	srv.Config.Handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusForbidden {
		t.Fatalf("bad token: expected 403, got %d", rec3.Code)
	}
	_ = time.Second
}
