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
