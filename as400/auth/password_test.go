package auth

import (
	"bytes"
	"testing"

	"crypto/sha512"
	"golang.org/x/crypto/pbkdf2"
)

// TestPBKDF2HMACSHA512MatchesReferenceImplementation cross-checks the
// dependency-free pbkdf2HMACSHA512 helper against golang.org/x/crypto's
// well-established implementation (a test-only dependency — not imported
// by any non-test file in this module).
func TestPBKDF2HMACSHA512MatchesReferenceImplementation(t *testing.T) {
	cases := []struct {
		password, salt []byte
		iterations     int
		keyLen         int
	}{
		{[]byte("password"), []byte("salt"), 1, 64},
		{[]byte("password"), []byte("salt"), 2, 64},
		{[]byte("a longer example password"), []byte{1, 2, 3, 4, 5, 6, 7, 8}, 4096, 64},
		{[]byte(""), []byte("salt"), 10022, 64},
		{[]byte("passwordPASSWORDpassword"), []byte("salt with more bytes than one block"), 10, 96},
	}
	for _, c := range cases {
		got := pbkdf2HMACSHA512(c.password, c.salt, c.iterations, c.keyLen)
		want := pbkdf2.Key(c.password, c.salt, c.iterations, c.keyLen, sha512.New)
		if !bytes.Equal(got, want) {
			t.Errorf("pbkdf2HMACSHA512(%q, %q, %d, %d) = % X, want % X",
				c.password, c.salt, c.iterations, c.keyLen, got, want)
		}
	}
}

func TestUTF16BE(t *testing.T) {
	got := UTF16BE("AB")
	want := []byte{0x00, 'A', 0x00, 'B'}
	if !bytes.Equal(got, want) {
		t.Errorf("UTF16BE(\"AB\") = % X, want % X", got, want)
	}
}

func TestPadOrTruncate(t *testing.T) {
	if got := padOrTruncate("AB", 5); got != "AB   " {
		t.Errorf("padOrTruncate(%q, 5) = %q, want %q", "AB", got, "AB   ")
	}
	if got := padOrTruncate("ABCDEFG", 5); got != "ABCDE" {
		t.Errorf("padOrTruncate(%q, 5) = %q, want %q", "ABCDEFG", got, "ABCDE")
	}
}

func TestEncryptPasswordDispatchesByLevel(t *testing.T) {
	var seed1, seed2 [8]byte
	seed1[0], seed2[0] = 1, 2

	for _, level := range []PasswordLevel{0, 1, 2, 3, 4, 5} {
		out, err := EncryptPassword(level, "USER1", "Sekret123", seed1, seed2)
		if err != nil {
			t.Fatalf("level %d: %v", level, err)
		}
		var wantLen int
		switch {
		case level < 2:
			wantLen = 8
		case level < 4:
			wantLen = 20
		default:
			wantLen = 64
		}
		if len(out) != wantLen {
			t.Errorf("level %d: len(authBytes) = %d, want %d", level, len(out), wantLen)
		}
	}
}
