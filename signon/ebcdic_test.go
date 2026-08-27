package signon

import "testing"

func TestEBCDIC10RoundTrip(t *testing.T) {
	cases := []string{"", "USER1", "QSECOFR", "A$B#C@D0"}
	for _, s := range cases {
		enc, err := encodeEBCDIC10(s)
		if err != nil {
			t.Fatalf("encodeEBCDIC10(%q): %v", s, err)
		}
		got := decodeEBCDIC10(enc)
		want := s
		for len(want) < 10 {
			want += " "
		}
		if got != want {
			t.Errorf("round trip %q: got %q, want %q", s, got, want)
		}
	}
}

func TestEBCDIC10KnownValues(t *testing.T) {
	enc, err := encodeEBCDIC10("A")
	if err != nil {
		t.Fatal(err)
	}
	if enc[0] != 0xC1 {
		t.Errorf("'A' encoded to %#x, want 0xC1", enc[0])
	}
	if enc[1] != 0x40 {
		t.Errorf("padding byte = %#x, want 0x40 (EBCDIC blank)", enc[1])
	}

	enc, err = encodeEBCDIC10("0")
	if err != nil {
		t.Fatal(err)
	}
	if enc[0] != 0xF0 {
		t.Errorf("'0' encoded to %#x, want 0xF0", enc[0])
	}
}

func TestEncodeEBCDIC10RejectsInvalidInput(t *testing.T) {
	if _, err := encodeEBCDIC10("12345678901"); err == nil {
		t.Error("expected an error for an 11-character input")
	}
	if _, err := encodeEBCDIC10("user!"); err == nil {
		t.Error("expected an error for a character outside the supported set")
	}
}
