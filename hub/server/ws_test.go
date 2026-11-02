// End-to-end J1 test: a REAL agent runtime connects over WebSocket (TLS with
// a self-signed hub cert — mTLS with the enrolled agent cert) and sends a
// heartbeat; the hub must update the host row.
//
// This is the golden-rule test: the agent initiates, the hub only answers.
package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
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

// startTLSServer runs the hub WS handler behind a TLS server requiring
// client certs issued by the hub CA (dev-equivalent of the Caddy path).
func startTLSServer(t *testing.T, s *Server) (serverURL string, tlsCfg *tls.Config) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/v1/ws", s.HandleWS)

	// Hub server cert (self-signed for localhost, signed by the hub CA).
	hubKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hubCertDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "central.test.fr"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}, s.CA.Cert, &hubKey.PublicKey, s.CA.Key)
	if err != nil {
		t.Fatal(err)
	}
	hubCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: hubCertDER})
	hubKeyDER, _ := x509.MarshalECPrivateKey(hubKey)
	hubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: hubKeyDER})
	cert, err := tls.X509KeyPair(hubCertPEM, hubKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	srv := &http.Server{ // #nosec G112 -- short-lived test server
		ReadHeaderTimeout: 5 * time.Second,
		Handler:           mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    s.ClientTLSConfig().ClientCAs,
			MinVersion:   tls.VersionTLS12,
		},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srv.TLSConfig)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }() //nolint:gosec // test server
	t.Cleanup(func() { _ = srv.Close() })

	// Client trust: hub CA + hub cert.
	pool := x509.NewCertPool()
	pool.AddCert(s.CA.Cert)
	u := "wss://" + ln.Addr().String() + "/agent/v1/ws"
	return u, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// TestAgentWebSocketHeartbeat enrolls a fake agent then runs the real
// runtime loop with a fast heartbeat and checks the DB gets updated.
func TestAgentWebSocketHeartbeat(t *testing.T) {
	s := testServer(t)
	_, _ = s.DB.Exec(`TRUNCATE enroll_tokens, hosts, telemetry RESTART IDENTITY`)

	// Enroll a test agent directly through the CA (no HTTP this time).
	raw, _, err := NewEnrollToken(s, "ws-test")
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
		HostCore: protocol.HostCore{Hostname: "ws-host-01", OS: "debian", AgentVersion: "t", AgentHash: "hash1"},
	})
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(body))
	s.HandleEnroll(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body.String())
	}
	var resp enroll.Response
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	agentID := resp.AgentID

	// Build the agent identity from the response (as the real agent persists it).
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: mustMarshalKey(key)})
	id := &enroll.Identity{
		AgentID: agentID, CertPEM: []byte(resp.Cert), KeyPEM: keyPEM, CAPool: []byte(resp.CA),
	}

	wsURL, _ := startTLSServer(t, s)
	id.HubURL = strings.Replace(wsURL, "/agent/v1/ws", "", 1)

	// Run the agent with a fast heartbeat (200 ms) and a short telemetry.
	cfg := runtime.Config{
		HeartbeatEvery: 200 * time.Millisecond,
		TelemetryEvery: 150 * time.Millisecond,
		InventoryEvery: time.Hour, // not in this test window
		MinBackoff:     time.Second,
		MaxBackoff:     2 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = runtime.Run(ctx, id, cfg) }()

	// Wait for the heartbeat to land.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var status string
		var lastSeen *time.Time
		err := s.DB.QueryRow(`SELECT status, last_seen FROM hosts WHERE id = $1`, agentID).Scan(&status, &lastSeen)
		if err == nil && status == "online" && lastSeen != nil {
			// Heartbeat arrived: host is online and last_seen set.
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("host never became online via WS heartbeat")
}

func mustMarshalKey(k *ecdsa.PrivateKey) []byte {
	der, _ := x509.MarshalECPrivateKey(k)
	return der
}
