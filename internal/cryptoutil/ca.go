// Package cryptoutil: TLS material for the agent↔hub channel (mTLS),
// including the hub-internal CA that signs agent certificates at enrollment
// (SPEC §6.1: token → CSR → certificate; private keys never leave the host
// that generated them).
package cryptoutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// NewAgentKey generates a fresh ECDSA P-256 private key on this machine.
// The key MUST be stored 0600 and never transmitted anywhere.
func NewAgentKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// CSRRequest builds a CSR for the agent key with the given agent ID as
// CommonName (the hub puts the agent UUID in the CN and SANs it).
func CSRRequest(key *ecdsa.PrivateKey, agentID string) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: agentID},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// InternalCA is the hub-side certificate authority for agent certs.
type InternalCA struct {
	Key     *ecdsa.PrivateKey
	Cert    *x509.Certificate
	CertPEM []byte
}

// NewInternalCA creates (or re-creates) the hub internal CA. Persisted on the
// hub volume; agent certificates chain to it.
func NewInternalCA(cn string, serial int64) (*InternalCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &InternalCA{
		Key:     key,
		Cert:    cert,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

// LoadOrCreateCA loads the internal CA from dir (ca.key + ca.crt, 0600) or
// creates it and persists it there. Dev/demo helper (HUB_CA_DIR): keeps agent
// identities valid across hub restarts. The volume-backed production
// persistence arrives with the keys volume (J10).
func LoadOrCreateCA(dir, cn string) (*InternalCA, error) {
	keyPath := filepath.Join(dir, "ca.key")
	certPath := filepath.Join(dir, "ca.crt")
	keyRaw, errKey := os.ReadFile(keyPath)    //nolint:gosec // fixed path built from dir
	certRaw, errCert := os.ReadFile(certPath) //nolint:gosec // idem
	if errKey == nil && errCert == nil {
		keyBlock, _ := pem.Decode(keyRaw)
		certBlock, _ := pem.Decode(certRaw)
		if keyBlock == nil || certBlock == nil {
			return nil, fmt.Errorf("cryptoutil: %s: invalid PEM", dir)
		}
		key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("cryptoutil: parse CA key: %w", err)
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("cryptoutil: parse CA cert: %w", err)
		}
		return &InternalCA{Key: key, Cert: cert, CertPEM: certRaw}, nil
	}
	ca, err := NewInternalCA(cn, time.Now().UnixNano())
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(ca.Key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, ca.CertPEM, 0o644); err != nil {
		return nil, err
	}
	return ca, nil
}

// SignAgentCert signs the CSR of an enrolling agent. serial and agentID are
// attributed by the hub (agent UUID); revocation is tracked by serial.
func (ca *InternalCA) SignAgentCert(csrPEM []byte, agentID string, serial int64) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("cryptoutil: invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cryptoutil: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("cryptoutil: CSR signature invalid: %w", err)
	}
	// The CN MUST match the agentID the hub decided — an agent cannot
	// impersonate another agent by putting its own CN in the CSR.
	if csr.Subject.CommonName != "" && csr.Subject.CommonName != agentID {
		return nil, fmt.Errorf("cryptoutil: CSR CN %q does not match attributed agent id", csr.Subject.CommonName)
	}
	serialBig := big.NewInt(serial)
	tmpl := &x509.Certificate{
		SerialNumber: serialBig,
		Subject:      pkix.Name{CommonName: agentID},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// SignHubCert signs the hub's own TLS server certificate with the internal
// CA. Used in dev/standalone mode (no reverse proxy): the agent trust store
// only contains the hub CA, so the server cert must chain to it too.
func (ca *InternalCA) SignHubCert(key *ecdsa.PrivateKey, names []string, serial int64) ([]byte, error) {
	serialBig := big.NewInt(serial)
	tmpl := &x509.Certificate{
		SerialNumber: serialBig,
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
	}
	// IP entries must go to IPAddresses (x509 requires it).
	ips := []net.IP{}
	dnsOnly := []string{}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsOnly = append(dnsOnly, n)
		}
	}
	tmpl.DNSNames = dnsOnly
	tmpl.IPAddresses = ips
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("cryptoutil: sign hub cert: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
