package signon

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// PasswordLevel mirrors the value the server returns during the
// exchange-attributes handshake (CP 0x1119): levels 0-1 use DES-based
// password substitution, 2-3 use SHA-1, and 4+ uses SHA-512/PBKDF2.
type PasswordLevel int

// signonSequence is the fixed initial sequence number used by every
// password scheme for a plain signon (as opposed to a change-password
// exchange, which increments it — not implemented by this library).
var signonSequence = [8]byte{0, 0, 0, 0, 0, 0, 0, 1}

// encryptPassword derives the authentication bytes sent as CP 0x1105 in a
// SignonInfoReq, using the scheme selected by level.
func encryptPassword(level PasswordLevel, userID, password string, clientSeed, serverSeed [8]byte) ([]byte, error) {
	switch {
	case level < 2:
		return encryptPasswordDES(userID, password, clientSeed, serverSeed)
	case level < 4:
		return encryptPasswordSHA1(userID, password, clientSeed, serverSeed)
	default:
		return encryptPasswordSHA512(userID, password, clientSeed, serverSeed)
	}
}

func encryptPasswordDES(userID, password string, clientSeed, serverSeed [8]byte) ([]byte, error) {
	if password != "" && password[0] >= '0' && password[0] <= '9' {
		password = "Q" + password
	}
	userIDBytes, err := encodeEBCDIC10(strings.ToUpper(userID))
	if err != nil {
		return nil, fmt.Errorf("signon: user id: %w", err)
	}
	pwBytes, err := encodeEBCDIC10(strings.ToUpper(password))
	if err != nil {
		return nil, fmt.Errorf("signon: password level 0/1 password: %w", err)
	}
	token := generateDESToken(userIDBytes, pwBytes)
	sub := generateDESPasswordSubstitute(userIDBytes, token, signonSequence, clientSeed, serverSeed)
	return sub[:], nil
}

func encryptPasswordSHA1(userID, password string, clientSeed, serverSeed [8]byte) ([]byte, error) {
	userIDBytes, err := encodeEBCDIC10(strings.ToUpper(userID))
	if err != nil {
		return nil, fmt.Errorf("signon: user id: %w", err)
	}
	userIDUTF16 := utf16BE(decodeEBCDIC10(userIDBytes))

	pw := trimTrailingUnicodeSpace(password)
	if pw == "" {
		return nil, fmt.Errorf("signon: password must not be empty")
	}
	if strings.HasPrefix(pw, "*") {
		return nil, fmt.Errorf("signon: password must not start with '*'")
	}
	pwBytes := utf16BE(pw)

	h := sha1.New()
	h.Write(userIDUTF16)
	h.Write(pwBytes)
	token := h.Sum(nil)

	h2 := sha1.New()
	h2.Write(token)
	h2.Write(serverSeed[:])
	h2.Write(clientSeed[:])
	h2.Write(userIDUTF16)
	h2.Write(signonSequence[:])
	return h2.Sum(nil), nil
}

// encryptPasswordSHA512 implements the password-level-4 scheme
// (AS400ImplRemote.generateSaltForPasswordLevel4 /
// generatePwdTokenForPasswordLevel4 / generateSha512Substitute). Unlike the
// DES and SHA-1 schemes, the user ID here is used in its original casing —
// not upper-cased, not restricted to the EBCDIC user-ID character set —
// only blank-padded/truncated to 10 characters, matching the Java source
// exactly.
//
// One detail could not be confirmed from the JTOpen source itself: the
// byte encoding PBEKeySpec/SunJCE's "PBKDF2WithHmacSHA512" uses internally
// to turn the char[] password into the byte string PBKDF2 operates on is a
// JDK/JCE-provider implementation detail, not JTOpen code. This
// implementation assumes the common SunJCE behavior of truncating each
// UTF-16 code unit to its low byte (Latin-1-equivalent for code points
// 0-255). For ASCII-only passwords — the overwhelming majority of real IBM
// i passwords — this is unambiguous and correct regardless of that
// assumption; only non-ASCII passwords under password level 4 carry
// residual risk and should be verified against a real pwdlvl-4 system
// before relying on this in production.
func encryptPasswordSHA512(userID, password string, clientSeed, serverSeed [8]byte) ([]byte, error) {
	profile := padOrTruncate(userID, 10)

	tail := password
	if len(tail) > 4 {
		tail = tail[len(tail)-4:]
	}
	saltSource := profile + padOrTruncate(tail, 4)
	salt := sha256.Sum256(utf16BE(saltSource))

	pwLatin1, err := latin1Bytes(password)
	if err != nil {
		return nil, fmt.Errorf("signon: password level 4 password: %w", err)
	}
	token := pbkdf2HMACSHA512(pwLatin1, salt[:], 10022, 64)

	h := sha512.New()
	h.Write(token)
	h.Write(serverSeed[:])
	h.Write(clientSeed[:])
	h.Write(utf16BE(profile))
	h.Write(signonSequence[:])
	return h.Sum(nil), nil
}

func padOrTruncate(s string, n int) string {
	r := []rune(s)
	if len(r) >= n {
		return string(r[:n])
	}
	return s + strings.Repeat(" ", n-len(r))
}

func latin1Bytes(s string) ([]byte, error) {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r > 0xFF {
			return nil, fmt.Errorf("character %q is outside the assumed Latin-1 range for password level 4", r)
		}
		out = append(out, byte(r))
	}
	return out, nil
}

func utf16BE(s string) []byte {
	units := utf16.Encode([]rune(s))
	buf := make([]byte, len(units)*2)
	for i, u := range units {
		binary.BigEndian.PutUint16(buf[i*2:], u)
	}
	return buf
}

func trimTrailingUnicodeSpace(s string) string {
	const ideographicSpace = "　"
	return strings.TrimRight(s, "\x00 "+ideographicSpace)
}

// pbkdf2HMACSHA512 is a from-scratch, dependency-free PBKDF2 (RFC 2898)
// implementation using HMAC-SHA512 as the PRF — a standard, publicly
// specified algorithm independent of JTOpen.
func pbkdf2HMACSHA512(password, salt []byte, iterations, keyLen int) []byte {
	prf := hmac.New(sha512.New, password)
	hLen := prf.Size()
	numBlocks := (keyLen + hLen - 1) / hLen
	dk := make([]byte, 0, numBlocks*hLen)
	block := make([]byte, 4)
	for i := 1; i <= numBlocks; i++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(block, uint32(i))
		prf.Write(block)
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for j := 1; j < iterations; j++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for k := range t {
				t[k] ^= u[k]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}
