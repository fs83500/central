package auth

import (
	"testing"
)

// TestPasswordHash verifies Argon2id round-trip + wrong password rejection.
func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(h, "correct horse battery staple") {
		t.Fatal("round-trip failed")
	}
	if VerifyPassword(h, "wrong password") {
		t.Fatal("wrong password accepted")
	}
	// garbage input must not panic
	if VerifyPassword("not-a-hash", "x") {
		t.Fatal("garbage hash accepted")
	}
}

// TestParseEncoded checks the encoded-format parser on a known vector.
func TestParseEncoded(t *testing.T) {
	h, err := HashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	p, salt, key, ok := parseEncoded(h)
	if !ok {
		t.Fatal("parse failed")
	}
	if p.Memory != 64*1024 || p.Time != 3 || p.Threads != 2 || p.KeyLen != 32 {
		t.Fatalf("params: %+v", p)
	}
	if len(salt) != 16 || len(key) != 32 {
		t.Fatalf("salt/key len: %d/%d", len(salt), len(key))
	}
}

// TestPad6 checks the MFA code formatting.
func TestPad6(t *testing.T) {
	cases := map[int]string{0: "000000", 1: "000001", 999999: "999999", 12345: "012345"}
	for in, want := range cases {
		if got := pad6(in); got != want {
			t.Fatalf("pad6(%d) = %q, want %q", in, got, want)
		}
	}
}
