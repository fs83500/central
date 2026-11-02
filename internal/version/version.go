// Package version exposes build metadata and the runtime self-hash (idea N12:
// agent integrity). The self-hash is embedded at build time by the Makefile
// (-ldflags) or computed at runtime as a fallback, and travels in every
// heartbeat so the hub can detect a tampered binary.
package version

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
)

// injected via -ldflags "-X ...version.gitCommit=... -X ...version.buildDate=..."
var (
	gitCommit = "dev"
	buildDate = "unknown"
	selfHash  = "" // set by Makefile after hashing the binary (re-link)
)

var (
	hashOnce sync.Once
	cached   string
)

// String returns the human-readable version.
func String() string {
	return fmt.Sprintf("%s (built %s)", gitCommit, buildDate)
}

// Commit returns the git commit the binary was built from.
func Commit() string {
	return gitCommit
}

// BuildDate returns the build timestamp.
func BuildDate() string {
	return buildDate
}

// SelfHash returns the SHA-256 of the running binary (hex). It prefers the
// build-time injected value; otherwise it hashes the executable on first use.
// On any failure it returns "(unknown)" — the hub treats an unknown hash with
// an alert, never silently.
func SelfHash() string {
	hashOnce.Do(func() {
		if selfHash != "" {
			cached = selfHash
			return
		}
		exe, err := os.Executable()
		if err != nil {
			cached = "(unknown)"
			return
		}
		/* #nosec G304 -- self-hash: path comes from os.Executable(), not user input */
		data, err := os.ReadFile(exe)
		if err != nil {
			cached = "(unknown)"
			return
		}
		sum := sha256.Sum256(data)
		cached = hex.EncodeToString(sum[:])
	})
	return cached
}
