package signon

import (
	"bytes"
	"crypto/des"
	"testing"
)

// TestEncDESKnownVector checks the underlying DES-ECB primitive (not the
// JTOpen-specific derivation chain, which has no available known-answer
// vector) against a widely published standard DES test vector: an all-zero
// key encrypting an all-zero block. This also confirms Go's crypto/des
// accepts an 8-byte key with no odd-parity requirement, which the JTOpen
// derivation depends on (its "keys" are arbitrary derived byte strings, not
// real parity-adjusted DES keys).
func TestEncDESKnownVector(t *testing.T) {
	var key, data [8]byte // all-zero key and plaintext
	got := encDES(key, data)
	want := []byte{0x8C, 0xA6, 0x4D, 0xE9, 0xC1, 0xB1, 0x23, 0xA7}
	if !bytes.Equal(got[:], want) {
		t.Errorf("encDES(zero key, zero block) = % X, want % X", got, want)
	}
}

func TestEncDESMatchesStdlib(t *testing.T) {
	key := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	data := [8]byte{8, 7, 6, 5, 4, 3, 2, 1}
	got := encDES(key, data)

	c, err := des.NewCipher(key[:])
	if err != nil {
		t.Fatalf("des.NewCipher: %v", err)
	}
	var want [8]byte
	c.Encrypt(want[:], data[:])
	if got != want {
		t.Errorf("encDES = % X, want % X (from crypto/des directly)", got, want)
	}
}

func TestXorWith0x55AndLshift(t *testing.T) {
	b := [8]byte{0, 0, 0, 0, 0, 0, 0, 0}
	xorWith0x55AndLshift(&b)
	// Every byte XOR 0x55 = 0x55, then the whole 8-byte value is shifted
	// left by one bit: 0x55 = 0b01010101 repeated; shifting the 64-bit
	// pattern left by 1 turns each 0x55 byte into 0xAA except carrying the
	// top bit of the next byte in.
	want := [8]byte{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}
	if b != want {
		t.Errorf("xorWith0x55AndLshift(zeros) = % X, want % X", b, want)
	}
}

func TestGenerateDESTokenIsDeterministic(t *testing.T) {
	userID, err := encodeEBCDIC10("QSECOFR")
	if err != nil {
		t.Fatal(err)
	}
	password, err := encodeEBCDIC10("SECRET1")
	if err != nil {
		t.Fatal(err)
	}
	t1 := generateDESToken(userID, password)
	t2 := generateDESToken(userID, password)
	if t1 != t2 {
		t.Error("generateDESToken is not deterministic for identical inputs")
	}

	otherPassword, _ := encodeEBCDIC10("SECRET2")
	t3 := generateDESToken(userID, otherPassword)
	if t1 == t3 {
		t.Error("generateDESToken produced the same token for two different passwords")
	}
}

func TestGenerateDESPasswordSubstituteVariesWithSeeds(t *testing.T) {
	userID, _ := encodeEBCDIC10("QSECOFR")
	password, _ := encodeEBCDIC10("SECRET1")
	token := generateDESToken(userID, password)

	seedA := [8]byte{1, 1, 1, 1, 1, 1, 1, 1}
	seedB := [8]byte{2, 2, 2, 2, 2, 2, 2, 2}

	sub1 := generateDESPasswordSubstitute(userID, token, signonSequence, seedA, seedB)
	sub2 := generateDESPasswordSubstitute(userID, token, signonSequence, seedA, seedB)
	if sub1 != sub2 {
		t.Error("generateDESPasswordSubstitute is not deterministic for identical inputs")
	}

	sub3 := generateDESPasswordSubstitute(userID, token, signonSequence, seedB, seedA)
	if sub1 == sub3 {
		t.Error("generateDESPasswordSubstitute did not change when client/server seeds were swapped")
	}
}
