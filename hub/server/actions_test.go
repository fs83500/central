// J3 integration tests: applicative ping (RTT measured hub-side) and the
// offline action queue (a pending action is delivered when the agent
// reconnects, and its result closes the row). Uses the same real TLS
// WebSocket + real agent runtime harness as ws_test.go.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"git.dpnac.cloud/dpnac/central/agent/enroll"
	"git.dpnac.cloud/dpnac/central/agent/runtime"
	"git.dpnac.cloud/dpnac/central/internal/cryptoutil"
	"git.dpnac.cloud/dpnac/central/internal/protocol"
)

// enrollTestAgent enrolls an agent via the CA path and returns its identity
// (agentID included) ready to run against the test hub.
func enrollTestAgent(t *testing.T, s *Server, hostname string) (*enroll.Identity, string) {
	t.Helper()
	// Shared test DB: wipe host state so the 5-host subscription quota
	// never bites (same contract as ws_test.go's TRUNCATE).
	_, _ = s.DB.Exec(`TRUNCATE actions, action_events, telemetry, hosts, enroll_tokens RESTART IDENTITY`)
	raw, _, err := NewEnrollToken(s, hostname)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cryptoutil.NewAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := cryptoutil.CSRRequest(key, "")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(enroll.Request{
		Token: raw, CSR: string(csr),
		HostCore: protocol.HostCore{Hostname: hostname, OS: "debian", AgentVersion: "t", AgentHash: "hash1"},
	})
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(body))
	s.HandleEnroll(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body.String())
	}
	var resp enroll.Response
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: mustMarshalKey(key)})
	id := &enroll.Identity{
		AgentID: resp.AgentID, CertPEM: []byte(resp.Cert), KeyPEM: keyPEM, CAPool: []byte(resp.CA),
	}
	return id, resp.AgentID
}

// TestPingOfflineAgent asserts the golden rule: the hub refuses to ping an
// agent that has no live connection (409, never dials out).
func TestPingOfflineAgent(t *testing.T) {
	s := testServer(t)
	_, agentID := enrollTestAgent(t, s, "ping-offline-01")

	rtt, err := s.SendPing(agentID)
	if err == nil {
		t.Fatalf("ping to offline agent must fail, got rtt=%d", rtt)
	}
	if !strings.Contains(err.Error(), "offline") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestPingLiveAgent runs the real agent, sends an applicative ping on the
// agent's socket and checks the measured RTT lands in hosts.rtt_ms.
func TestPingLiveAgent(t *testing.T) {
	s := testServer(t)
	id, agentID := enrollTestAgent(t, s, "ping-live-01")

	wsURL, _ := startTLSServer(t, s)
	id.HubURL = strings.Replace(wsURL, "/agent/v1/ws", "", 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = runtime.Run(ctx, id, runtime.Config{
			HeartbeatEvery: 500 * time.Millisecond,
			TelemetryEvery: time.Hour,
			InventoryEvery: time.Hour,
			MinBackoff:     time.Second,
			MaxBackoff:     2 * time.Second,
		})
	}()

	// Wait until the registry sees the live connection.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.liveConn(agentID) != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if s.liveConn(agentID) == nil {
		t.Fatal("agent never connected")
	}

	rtt, err := s.SendPing(agentID)
	if err != nil {
		t.Fatalf("SendPing: %v", err)
	}
	if rtt < 0 {
		t.Fatalf("rtt must be >= 0, got %d", rtt)
	}
	var stored *int
	_ = s.DB.QueryRow(`SELECT rtt_ms FROM hosts WHERE id = $1`, agentID).Scan(&stored)
	if stored == nil || *stored < 0 {
		t.Fatalf("rtt_ms not stored: %v", stored)
	}
}

// TestActionQueuedOfflineDeliveredOnReconnect queues an action while the
// agent is offline, then connects the agent: the hub must deliver the action
// on the agent's socket and the agent's action_result must close the row.
func TestActionQueuedOfflineDeliveredOnReconnect(t *testing.T) {
	s := testServer(t)
	id, agentID := enrollTestAgent(t, s, "action-queue-01")

	// 1. Agent offline → enqueue (stays pending).
	actionID, err := s.enqueueAction(agentID, "inventory_refresh", nil, "admin@test.fr")
	if err != nil {
		t.Fatal(err)
	}
	var status string
	_ = s.DB.QueryRow(`SELECT status FROM actions WHERE id = $1`, actionID).Scan(&status)
	if status != "pending" {
		t.Fatalf("offline action must stay pending, got %q", status)
	}
	// Also check the not-null payload survived as an empty JSON object.
	var payload []byte
	_ = s.DB.QueryRow(`SELECT payload FROM actions WHERE id = $1`, actionID).Scan(&payload)
	if string(payload) != "{}" {
		t.Fatalf("payload must default to {}, got %s", payload)
	}

	// 2. Connect the real agent.
	wsURL, _ := startTLSServer(t, s)
	id.HubURL = strings.Replace(wsURL, "/agent/v1/ws", "", 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = runtime.Run(ctx, id, runtime.Config{
			HeartbeatEvery: time.Hour, // silent loop: no heartbeat noise
			TelemetryEvery: time.Hour,
			InventoryEvery: time.Hour,
			MinBackoff:     time.Second,
			MaxBackoff:     2 * time.Second,
		})
	}()

	// 3. The action must be delivered then completed (done) by the agent.
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		_ = s.DB.QueryRow(`SELECT status FROM actions WHERE id = $1`, actionID).Scan(&status)
		if status == "done" {
			var result []byte
			_ = s.DB.QueryRow(`SELECT result FROM actions WHERE id = $1`, actionID).Scan(&result)
			var inv protocol.Inventory
			if err := json.Unmarshal(result, &inv); err != nil {
				t.Fatalf("action result must be an inventory payload, got %s", result)
			}
			// In the CI container dpkg status may not exist → nil slices are
			// valid. What matters is the payload SHAPE (j3 collector contract).
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("action never completed, status=%q", status)
}

// TestCompleteActionOwnership verifies an agent cannot close another host's
// action (action rows are host-scoped).
func TestCompleteActionOwnership(t *testing.T) {
	s := testServer(t)
	// Enroll agent A only — enrollments wipe hosts (shared test DB +
	// 5-host quota), so two live hosts cannot coexist; the foreign-agent
	// probe below covers the actual attack (someone else's agent closing
	// the action).
	_, agentA := enrollTestAgent(t, s, "action-owner-a")
	actionID, err := s.enqueueAction(agentA, "pkg_list", nil, "admin@test.fr")
	if err != nil {
		t.Fatal(err)
	}
	foreign := "00000000-0000-0000-0000-0000000000ff"
	err = s.completeAction(foreign, protocol.ActionResult{ID: actionID, Status: "done"})
	if err == nil {
		t.Fatal("a foreign agent must not close this action")
	}
	err = s.completeAction(agentA, protocol.ActionResult{ID: actionID, Status: "done"})
	if err != nil {
		t.Fatalf("owner must close its action: %v", err)
	}
}

// TestUnknownActionTypeRejected keeps the J3 whitelist tight: the API refuses
// to queue pkg_update (J4) or anything else before it exists.
func TestUnknownActionTypeRejected(t *testing.T) {
	s := testServer(t)
	_, agentID := enrollTestAgent(t, s, "action-whitelist-01")
	if _, err := s.enqueueAction(agentID, "pkg_update", nil, "x"); err == nil {
		t.Fatal("pkg_update must not be queueable in J3")
	}
	// enqueueAction is liberal (it feeds the agent which itself refuses);
	// the HTTP handler is the strict gate — check its whitelist directly.
	if err := validateActionType("pkg_update"); err == nil {
		t.Fatal("handler whitelist must reject pkg_update")
	}
	if err := validateActionType("inventory_refresh"); err != nil {
		t.Fatalf("inventory_refresh must pass: %v", err)
	}
}
