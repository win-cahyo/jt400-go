// Package auth implements the password-encryption schemes and EBCDIC
// user-ID encoding shared by every IBM i host-server logon: the
// exchange-attributes + start-server handshake used by as-dtaq and
// as-rmtcmd, and the exchange-attributes + signon-info exchange used by
// as-signon. It exists as its own package (rather than living inside
// signon) purely so as400's generic connection-startup helper and the
// signon package can both depend on it without an import cycle.
package auth

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

// EncodeEBCDIC encodes s into unpadded EBCDIC, restricted to the same
// character set as EncodeEBCDIC10 (A-Z, 0-9, space, $ # @). This covers
// IBM i simple object names (queue/library names, search-type codes) but
// not arbitrary free text such as a text description, which may contain
// characters outside this set — callers encoding free text should expect
// EncodeEBCDIC to reject them rather than silently drop or mistranslate.
func EncodeEBCDIC(s string) ([]byte, error) {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		e, ok := asciiToEBCDIC[s[i]]
		if !ok {
			return nil, fmt.Errorf("character %q is not valid in this library's restricted EBCDIC character set (A-Z, 0-9, space, $ # @)", s[i])
		}
		out[i] = e
	}
	return out, nil
}

// EncodeEBCDICPadded encodes s like EncodeEBCDIC, then blank(0x40)-pads (or
// rejects, if s is longer) the result to exactly n bytes.
func EncodeEBCDICPadded(s string, n int) ([]byte, error) {
	if len(s) > n {
		return nil, fmt.Errorf("%q is longer than %d characters", s, n)
	}
	enc, err := EncodeEBCDIC(s)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	for i := range out {
		out[i] = 0x40
	}
	copy(out, enc)
	return out, nil
}

// EncodeEBCDIC10 encodes s (expected already upper-cased by the caller
// where case matters) into a 10-byte, blank(0x40)-padded EBCDIC field, as
// used for the user ID and password-level-0/1 password fields on the wire.
func EncodeEBCDIC10(s string) ([10]byte, error) {
	var out [10]byte
	b, err := EncodeEBCDICPadded(s, 10)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

// DecodeEBCDIC10 is the inverse of EncodeEBCDIC10. Every byte produced by
// EncodeEBCDIC10 is guaranteed present in the reverse map, so round-tripping
// our own output never hits the fallback path.
func DecodeEBCDIC10(b [10]byte) string {
	return DecodeEBCDICLossy(b[:])
}

// DecodeEBCDICLossy decodes a server-supplied EBCDIC field (e.g. a job
// name) that may contain characters outside the restricted set this
// library otherwise validates against. Unmappable bytes become '?' — this
// is only used for informational fields, never for values that feed a
// cryptographic derivation.
func DecodeEBCDICLossy(b []byte) string {
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
