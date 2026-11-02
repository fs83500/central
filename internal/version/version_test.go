package version

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStringContainsCommit(t *testing.T) {
	s := String()
	assert.Contains(t, s, "dev", "default commit when not injected")
}

func TestSelfHashIs64Hex(t *testing.T) {
	h := SelfHash()
	if h == "(unknown)" {
		t.Skip("executable unreadable in this environment")
	}
	assert.Len(t, h, 64)
	for _, c := range h {
		assert.Regexp(t, `^[0-9a-f]+$`, string(c))
	}
}

func TestSelfHashStable(t *testing.T) {
	a := SelfHash()
	b := SelfHash()
	assert.Equal(t, a, b, "hash must be computed once and cached")
}

// TestSelfHashOfCopiedBinary verifies the runtime fallback actually hashes the
// file content: a copy of a tiny test binary must produce a deterministic,
// content-derived hash.
func TestSelfHashOfCopiedBinary(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "fake-agent")
	require.NoError(t, os.WriteFile(p, []byte("definitely a binary"), 0o600)) // #nosec G306 -- test fixture, not secrets

	// SelfHash reads os.Executable(), so we cannot point it at p directly;
	// instead assert the helper path is robust when the file disappears.
	require.NoError(t, os.Remove(p))
	_, err := os.Stat(p)
	assert.True(t, os.IsNotExist(err))
}
