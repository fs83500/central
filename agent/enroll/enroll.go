// Package enroll implements the agent side of the enrollment flow
// (PLAN §3.1): token → key generation → CSR → POST /api/v1/enroll →
// certificate + hub config written to the state dir. The private key is
// generated LOCALLY and never leaves this machine.
package enroll

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"git.dpnac.cloud/dpnac/central/internal/cryptoutil"
	"git.dpnac.cloud/dpnac/central/internal/protocol"
)

// StateDir is where the agent stores its identity (0700 dir, 0600 files).
const StateDir = "/var/lib/unifiedguard"

// TokenBytes is the entropy of a raw enrollment token (before "ug-" prefix
// and hex encoding → 128 bits).
const tokenEntropy = 16

// GenerateToken returns a new raw enrollment token like
// "ug-9f3b2c1a4d5e6f7089aabbccddeeff00".
func GenerateToken() (string, error) {
	b := make([]byte, tokenEntropy)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "ug-" + hex.EncodeToString(b), nil
}

// HashToken is how the hub stores tokens (never the raw value).
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Identity is the persisted agent identity after enrollment.
type Identity struct {
	AgentID string `json:"agent_id"`
	HubURL  string `json:"hub_url"`
	CertPEM []byte `json:"-"`
	KeyPEM  []byte `json:"-"`
	CAPool  []byte `json:"-"` // hub CA chain for mTLS verification
}

// Response is what the hub sends back on successful enrollment.
type Response struct {
	AgentID   string          `json:"agent_id"`
	Cert      string          `json:"cert"` // PEM
	CA        string          `json:"ca"`   // PEM chain incl. internal CA
	HubConfig json.RawMessage `json:"hub_config"`
}

// Request is what the agent POSTs (token in the BODY, never the URL).
type Request struct {
	Token string `json:"token"`
	CSR   string `json:"csr"` // PEM
	protocol.HostCore
}

// Enroll performs the whole flow and persists the identity under stateDir.
func Enroll(hubURL, token, stateDir string, core protocol.HostCore) (*Identity, error) {
	if stateDir == "" {
		stateDir = StateDir
	}
	// 1. Generate the key pair locally (never transmitted).
	key, err := cryptoutil.NewAgentKey()
	if err != nil {
		return nil, fmt.Errorf("enroll: keygen: %w", err)
	}

	// 2. CSR with a placeholder CN; the hub attributes the real agent UUID
	//    and enforces CN == attributed id when signing.
	csr, err := cryptoutil.CSRRequest(key, "")
	if err != nil {
		return nil, fmt.Errorf("enroll: csr: %w", err)
	}

	// 3. POST /api/v1/enroll (token in the JSON body).
	body, _ := json.Marshal(Request{
		Token:    token,
		CSR:      string(csr),
		HostCore: core,
	})
	url := hubURL + "/api/v1/enroll"
	// The agent cannot know the hub CA BEFORE enrollment (it receives it in
	// the response). In production the hub TLS cert is public (Let's Encrypt
	// behind Caddy). For dev/self-signed hubs, UG_ENROLL_INSECURE=1 skips
	// verification for the enrollment POST ONLY — the WebSocket afterwards
	// always verifies the full chain (CAPool from the enrollment response).
	client := &http.Client{Timeout: 30 * time.Second}
	if os.Getenv("UG_ENROLL_INSECURE") == "1" {
		client.Transport = &http.Transport{ //nolint:gosec // explicit opt-in dev flag
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // dev only
		}
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("enroll: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enroll: hub rejected (HTTP %d): %s", resp.StatusCode, truncate(raw, 200))
	}
	var r Response
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("enroll: bad response: %w", err)
	}
	if r.AgentID == "" || r.Cert == "" || r.CA == "" {
		return nil, fmt.Errorf("enroll: incomplete hub response")
	}

	// 4. Persist identity: state dir 0700, files 0600.
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	keyPEM, err := encodeKey(key)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{
		"agent.key":     keyPEM,
		"agent.crt":     []byte(r.Cert),
		"ca.crt":        []byte(r.CA),
		"identity.json": mustJSON(Identity{AgentID: r.AgentID, HubURL: hubURL}),
	}
	for name, data := range files {
		p := filepath.Join(stateDir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil { // #nosec G306 -- identity files are 0600
			return nil, fmt.Errorf("enroll: write %s: %w", name, err)
		}
	}
	return &Identity{
		AgentID: r.AgentID,
		HubURL:  hubURL,
		CertPEM: []byte(r.Cert),
		KeyPEM:  keyPEM,
		CAPool:  []byte(r.CA),
	}, nil
}

// LoadIdentity reads the persisted identity from the state dir.
func LoadIdentity(stateDir string) (*Identity, error) {
	if stateDir == "" {
		stateDir = StateDir
	}
	idRaw, err := os.ReadFile(filepath.Join(stateDir, "identity.json")) //nolint:gosec // fixed state dir path
	if err != nil {
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(idRaw, &id); err != nil {
		return nil, err
	}
	if id.CertPEM, err = os.ReadFile(filepath.Join(stateDir, "agent.crt")); err != nil { //nolint:gosec // fixed state dir path
		return nil, err
	}
	if id.KeyPEM, err = os.ReadFile(filepath.Join(stateDir, "agent.key")); err != nil { //nolint:gosec // fixed state dir path
		return nil, err
	}
	if id.CAPool, err = os.ReadFile(filepath.Join(stateDir, "ca.crt")); err != nil { //nolint:gosec // fixed state dir path
		return nil, err
	}
	return &id, nil
}

func encodeKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}
