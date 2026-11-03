// sitekey.go — J4 (SPEC §6.3): site key pair + snapshot envelope encryption.
//
// Model: each hub (site) owns an RSA-2048 key pair. Agents encrypt firewall
// snapshots ON THE HOST with a random AES-256-GCM data key, then wrap the data
// key with the SITE PUBLIC key (RSA-OAEP-SHA256). The hub stores the opaque
// blob; only the site private key — which never leaves this hub — can open it.
// Restore is hub-side: unwrap, check SHA-256, send the plaintext ruleset back
// to an agent of the same site over the mTLS channel.

package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SiteKey is the site key pair (private key NEVER leaves the hub process/db).
type SiteKey struct {
	Private     *rsa.PrivateKey
	PublicPEM   []byte
	PrivatePEM  []byte
	Fingerprint string // sha256(public PEM)
}

// GenerateSiteKey creates the site RSA-2048 key pair.
func GenerateSiteKey() (*SiteKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("sitekey: generate: %w", err)
	}
	return newSiteKey(priv)
}

func newSiteKey(priv *rsa.PrivateKey) (*SiteKey, error) {
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("sitekey: marshal pub: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	sum := sha256.Sum256(pubPEM)
	return &SiteKey{
		Private:     priv,
		PublicPEM:   pubPEM,
		PrivatePEM:  privPEM,
		Fingerprint: hex.EncodeToString(sum[:]),
	}, nil
}

// ParseSiteKey rebuilds a SiteKey from stored PEMs (hub boot / restore).
func ParseSiteKey(publicPEM, privatePEM []byte) (*SiteKey, error) {
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return nil, errors.New("sitekey: bad private PEM")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sitekey: parse private: %w", err)
	}
	sk, err := newSiteKey(priv)
	if err != nil {
		return nil, err
	}
	if string(publicPEM) != string(sk.PublicPEM) {
		return nil, errors.New("sitekey: public/private mismatch")
	}
	return sk, nil
}

// LoadOrCreateSiteKeyFile loads the site key pair from <dir>/site-key.pem,
// creating it (0600) on first run. SPEC §6.3: the private key NEVER leaves
// the centrale — this file lives on a hub Docker volume, the DB only ever
// sees the public key. The file holds BOTH PEMs so the pair is self-checked
// at load time (a mismatch would mean corruption or tampering).
func LoadOrCreateSiteKeyFile(dir string) (*SiteKey, bool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, fmt.Errorf("sitekey: mkdir: %w", err)
	}
	path := filepath.Join(dir, "site-key.pem")
	if b, err := os.ReadFile(path); err == nil {
		priv, pub := splitSiteKeyPEM(b)
		if priv == nil || pub == nil {
			return nil, false, errors.New("sitekey: key file malformed")
		}
		sk, err := ParseSiteKey(pub, priv)
		if err != nil {
			return nil, false, err
		}
		return sk, false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("sitekey: read: %w", err)
	}
	sk, err := GenerateSiteKey()
	if err != nil {
		return nil, false, err
	}
	blob := append(append([]byte{}, sk.PrivatePEM...), sk.PublicPEM...)
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		return nil, false, fmt.Errorf("sitekey: write: %w", err)
	}
	return sk, true, nil
}

// splitSiteKeyPEM extracts the FIRST "RSA PRIVATE KEY" block and the FIRST
// "PUBLIC KEY" block from a combined PEM blob.
func splitSiteKeyPEM(b []byte) (priv, pub []byte) {
	rest := b
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return
		}
		switch block.Type {
		case "RSA PRIVATE KEY":
			if priv == nil {
				priv = pem.EncodeToMemory(block)
			}
		case "PUBLIC KEY":
			if pub == nil {
				pub = pem.EncodeToMemory(block)
			}
		}
		if priv != nil && pub != nil {
			return
		}
	}
}

// SnapshotSeal is one sealed snapshot (what the agent produces).
type SnapshotSeal struct {
	Ciphertext []byte
	Nonce      []byte
	WrappedKey []byte
	SHA256     string // digest of the PLAINTEXT ruleset
	SizeBytes  int
}

// SealSnapshot encrypts the plaintext with a fresh AES-256-GCM data key,
// then wraps the data key with the site public key. Used BY AGENTS.
func SealSnapshot(sitePubPEM, plaintext []byte) (*SnapshotSeal, error) {
	pub, err := ParsePublicRSA(sitePubPEM)
	if err != nil {
		return nil, err
	}
	dataKey := make([]byte, 32) // AES-256
	if _, err := rand.Read(dataKey); err != nil {
		return nil, fmt.Errorf("sitekey: data key: %w", err)
	}
	nonce := make([]byte, 12) // GCM standard
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("sitekey: nonce: %w", err)
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, dataKey, []byte("ug-fw-snapshot"))
	if err != nil {
		return nil, fmt.Errorf("sitekey: wrap: %w", err)
	}
	sum := sha256.Sum256(plaintext)
	return &SnapshotSeal{
		Ciphertext: ct, Nonce: nonce, WrappedKey: wrapped,
		SHA256: hex.EncodeToString(sum[:]), SizeBytes: len(plaintext),
	}, nil
}

// UnsealSnapshot opens a sealed snapshot with the site PRIVATE key (hub only).
func (sk *SiteKey) UnsealSnapshot(seal *SnapshotSeal) ([]byte, error) {
	dataKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, sk.Private, seal.WrappedKey, []byte("ug-fw-snapshot"))
	if err != nil {
		return nil, fmt.Errorf("sitekey: unwrap: %w", err)
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, seal.Nonce, seal.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("sitekey: open: %w", err)
	}
	sum := sha256.Sum256(pt)
	if hex.EncodeToString(sum[:]) != seal.SHA256 {
		return nil, errors.New("sitekey: snapshot digest mismatch")
	}
	return pt, nil
}

// ParsePublicRSA parses a PEM public key (agent side).
func ParsePublicRSA(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("sitekey: bad public PEM")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sitekey: parse public: %w", err)
	}
	pub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("sitekey: not an RSA public key")
	}
	return pub, nil
}
