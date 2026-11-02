// Package auth implements hub user auth (SPEC §4.1): e-mail identity,
// Argon2id password hashing, double opt-in activation, MFA e-mail codes,
// sessions with absolute + inactivity TTL, login rate limiting.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Params are the Argon2id parameters (SPEC §4.1.5 — Argon2id mandatory).
type Params struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
	KeyLen  uint32
}

// DefaultParams: 64 MiB, t=3, p=2, 32-byte key — calibrated for a hub VM.
func DefaultParams() Params { return Params{Memory: 64 * 1024, Time: 3, Threads: 2, KeyLen: 32} }

// HashPassword derives an Argon2id encoded hash ("$argon2id$v=19$m=…,t=…,p=…$salt$hash").
func HashPassword(password string) (string, error) {
	p := DefaultParams()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return formatEncoded(p, salt, key), nil
}

// VerifyPassword checks a password against an encoded Argon2id hash.
func VerifyPassword(encoded, password string) bool {
	p, salt, want, ok := parseEncoded(encoded)
	if !ok {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func formatEncoded(p Params, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

func parseEncoded(s string) (p Params, salt, key []byte, ok bool) {
	// $argon2id$v=19$m=65536,t=3,p=2$<salt>$<key>
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || !strings.HasPrefix(parts[2], "v=") {
		return p, nil, nil, false
	}
	// parse "m=65536,t=3,p=2"
	var m, t, th int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &th); err != nil {
		return p, nil, nil, false
	}
	p.Memory, p.Time, p.Threads = uint32(m), uint32(t), uint8(th)
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, false
	}
	key, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return p, nil, nil, false
	}
	p.KeyLen = uint32(len(key))
	return p, salt, key, true
}

// HashToken returns the hex SHA-256 of a raw token (used for sessions,
// activation and MFA codes — high-entropy random values: SHA-256 is enough).
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// NewRawToken returns a URL-safe random token of nBytes entropy.
func NewRawToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// TTLs (SPEC §4.1.5): 8 h absolute session, 30 min inactivity, 24 h
// activation link, 10 min MFA code.
const (
	SessionAbsTTL  = 8 * time.Hour
	SessionIdleTTL = 30 * time.Minute
	ActivationTTL  = 24 * time.Hour
	MFACodeTTL     = 10 * time.Minute
)

// LoginThrottle: 5 failures → lock with exponential backoff (SPEC §4.1.5).
const LoginMaxFailures = 5

// ThrottleState tells the login handler whether to refuse and until when.
type ThrottleState struct {
	Failures int
	Locked   bool
	RetryAt  time.Time
}

// CheckLoginThrottle counts recent failures for (email, ip). Locked after
// 5 failures in the last 15 minutes; retry time uses exponential backoff.
func CheckLoginThrottle(db *sql.DB, email, ip string) ThrottleState {
	var failures int
	err := db.QueryRow(`
		SELECT count(*) FROM hub_login_attempts
		WHERE email = $1 AND ip = $2 AND ok = FALSE AND at > now() - interval '15 minutes'`,
		email, ip).Scan(&failures)
	if err != nil {
		return ThrottleState{}
	}
	if failures >= LoginMaxFailures {
		var last time.Time
		_ = db.QueryRow(`
			SELECT max(at) FROM hub_login_attempts
			WHERE email = $1 AND ip = $2 AND ok = FALSE`, email, ip).Scan(&last)
		over := failures - LoginMaxFailures
		mins := 1 << over
		if mins > 15 {
			mins = 15
		}
		return ThrottleState{Failures: failures, Locked: true, RetryAt: last.Add(time.Duration(mins) * time.Minute)}
	}
	return ThrottleState{Failures: failures}
}

// RecordAttempt logs a login attempt (audit trail + throttle source).
func RecordAttempt(db *sql.DB, email, ip string, ok bool) {
	_, _ = db.Exec(`INSERT INTO hub_login_attempts (email, ip, ok) VALUES ($1, $2, $3)`, email, ip, ok)
}

// User is the hub_users row subset the app uses.
type User struct {
	ID       int64
	Email    string
	Role     string
	IsActive bool
	Theme    string
}
