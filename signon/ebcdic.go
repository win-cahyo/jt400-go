package signon

import "fmt"

// asciiToEBCDIC/ebcdicToASCII cover exactly the character set JTOpen's
// SignonConverter documents as valid for a user ID or a password-level-0/1
// password: A-Z, 0-9, space, and the AS/400 special name characters $ # @.
// Values are the standard EBCDIC CCSID 37 (US English) code page, a public
// IBM code page specification independent of JTOpen.
var asciiToEBCDIC = buildASCIIToEBCDIC()
var ebcdicToASCII = buildEBCDICToASCII()

func buildASCIIToEBCDIC() map[byte]byte {
	m := map[byte]byte{' ': 0x40, '$': 0x5B, '#': 0x7B, '@': 0x7C}
	for i := 0; i < 9; i++ {
		m[byte('A'+i)] = byte(0xC1 + i) // A-I
	}
	for i := 0; i < 9; i++ {
		m[byte('J'+i)] = byte(0xD1 + i) // J-R
	}
	for i := 0; i < 8; i++ {
		m[byte('S'+i)] = byte(0xE2 + i) // S-Z
	}
	for i := 0; i < 10; i++ {
		m[byte('0'+i)] = byte(0xF0 + i)
	}
	return m
}

func buildEBCDICToASCII() map[byte]byte {
	m := make(map[byte]byte, len(asciiToEBCDIC))
	for a, e := range asciiToEBCDIC {
		m[e] = a
	}
	return m
}

// encodeEBCDIC10 encodes s (expected already upper-cased by the caller
// where case matters) into a 10-byte, blank(0x40)-padded EBCDIC field, as
// used for the user ID and password-level-0/1 password fields on the wire.
func encodeEBCDIC10(s string) ([10]byte, error) {
	var out [10]byte
	for i := range out {
		out[i] = 0x40
	}
	if len(s) > 10 {
		return out, fmt.Errorf("%q is longer than 10 characters", s)
	}
	for i := 0; i < len(s); i++ {
		e, ok := asciiToEBCDIC[s[i]]
		if !ok {
			return out, fmt.Errorf("character %q is not valid in a user ID or password-level-0/1 password", s[i])
		}
		out[i] = e
	}
	return out, nil
}

// decodeEBCDIC10 is the inverse of encodeEBCDIC10. Every byte produced by
// encodeEBCDIC10 is guaranteed present in the reverse map, so round-tripping
// our own output never hits the fallback path.
func decodeEBCDIC10(b [10]byte) string {
	return decodeEBCDICLossy(b[:])
}

// decodeEBCDICLossy decodes a server-supplied EBCDIC field (e.g. a job
// name) that may contain characters outside the restricted set this
// library otherwise validates against. Unmappable bytes become '?' — this
// is only used for informational fields, never for values that feed a
// cryptographic derivation.
func decodeEBCDICLossy(b []byte) string {
	out := make([]byte, len(b))
	for i, e := range b {
		if a, ok := ebcdicToASCII[e]; ok {
			out[i] = a
		} else {
			out[i] = '?'
		}
	}
	return string(out)
}
