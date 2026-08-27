package signon

import "crypto/des"

// This file implements the password-level-0/1 "password substitute"
// scheme, transcribed field-for-field from
// AS400ImplRemote.generateToken/generatePasswordSubstitute/enc_des/
// xorWith0x55andLshift/addArray in the JTOpen source (verified against the
// exact source lines, not a paraphrase). JTOpen hand-rolls DES there only
// because Java's javax.crypto DES key classes enforce odd-parity key bytes,
// which these derived 8-byte "tokens" don't satisfy; standard DES (as
// implemented by Go's crypto/des, which does not enforce key parity) is the
// same algorithm and produces identical output for a given key/block.
//
// Password level 0/1 is IBM i's legacy (pre-SHA) authentication scheme.
// This implementation follows the documented algorithm exactly, but has
// not been exercised against a live password-level-0/1 system — verify
// against a real system before relying on it in production.

// encDES performs one single-block DES-ECB encryption: enc_des(key, data)
// in the JTOpen source.
func encDES(key, data [8]byte) [8]byte {
	c, err := des.NewCipher(key[:])
	if err != nil {
		// key is always exactly 8 bytes, the only way NewCipher can fail.
		panic("as400/signon: unreachable: " + err.Error())
	}
	var out [8]byte
	c.Encrypt(out[:], data[:])
	return out
}

// xorWith0x55AndLshift XORs every byte with 0x55, then left-shifts the
// whole 8-byte value by one bit (treating it as one big-endian 64-bit
// number), matching AS400ImplRemote.xorWith0x55andLshift exactly.
func xorWith0x55AndLshift(b *[8]byte) {
	for i := range b {
		b[i] ^= 0x55
	}
	var shifted [8]byte
	for i := 0; i < 7; i++ {
		shifted[i] = b[i]<<1 | (b[i+1]&0x80)>>7
	}
	shifted[7] = b[7] << 1
	*b = shifted
}

func xorArray8(a, b [8]byte) [8]byte {
	var out [8]byte
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// addArray8 adds a and b as big-endian 64-bit numbers with carry, matching
// AS400ImplRemote.addArray.
func addArray8(a, b [8]byte) [8]byte {
	var out [8]byte
	carry := 0
	for i := 7; i >= 0; i-- {
		sum := int(a[i]) + int(b[i]) + carry
		carry = sum >> 8
		out[i] = byte(sum)
	}
	return out
}

// ebcdicFieldLen returns the length of an EBCDIC field up to its first
// blank (0x40) or NUL terminator, matching AS400ImplRemote.ebcdicStrLen.
func ebcdicFieldLen(b [10]byte) int {
	i := 0
	for i < len(b) && b[i] != 0x40 && b[i] != 0x00 {
		i++
	}
	return i
}

// generateDESToken implements AS400ImplRemote.generateToken.
func generateDESToken(userID, password [10]byte) [8]byte {
	work1 := userID
	if ebcdicFieldLen(userID) > 8 {
		work1[0] ^= work1[8] & 0xC0
		work1[1] ^= (work1[8] & 0x30) << 2
		work1[2] ^= (work1[8] & 0x0C) << 4
		work1[3] ^= (work1[8] & 0x03) << 6
		work1[4] ^= work1[9] & 0xC0
		work1[5] ^= (work1[9] & 0x30) << 2
		work1[6] ^= (work1[9] & 0x0C) << 4
		work1[7] ^= (work1[9] & 0x03) << 6
	}
	var foldedUserID [8]byte
	copy(foldedUserID[:], work1[:8])

	pwLen := ebcdicFieldLen(password)
	if pwLen > 8 {
		var half1, half2 [8]byte
		copy(half1[:], password[:8])
		for i := range half2 {
			half2[i] = 0x40
		}
		copy(half2[:], password[8:pwLen])
		xorWith0x55AndLshift(&half1)
		xorWith0x55AndLshift(&half2)
		t1 := encDES(half1, foldedUserID)
		t2 := encDES(half2, foldedUserID)
		return xorArray8(t1, t2)
	}

	var buf [8]byte
	for i := range buf {
		buf[i] = 0x40
	}
	copy(buf[:], password[:pwLen])
	xorWith0x55AndLshift(&buf)
	return encDES(buf, foldedUserID)
}

// generateDESPasswordSubstitute implements
// AS400ImplRemote.generatePasswordSubstitute (the SNA/LU6.2 CBC-MAC-style
// password substitute formula).
func generateDESPasswordSubstitute(userID [10]byte, token, sequenceNumber, clientSeed, serverSeed [8]byte) [8]byte {
	rdrSeq := addArray8(sequenceNumber, serverSeed)

	enc := encDES(token, rdrSeq)
	next := xorArray8(enc, clientSeed)
	enc = encDES(token, next) // "password verifier"; not used further, matching JTOpen

	var userIDFirst8 [8]byte
	copy(userIDFirst8[:], userID[:8])
	next = xorArray8(userIDFirst8, rdrSeq)
	next = xorArray8(next, enc)
	enc = encDES(token, next)

	var tail [8]byte
	for i := range tail {
		tail[i] = 0x40
	}
	tail[0], tail[1] = userID[8], userID[9]
	next = xorArray8(rdrSeq, tail)
	next = xorArray8(next, enc)
	enc = encDES(token, next)

	next = xorArray8(sequenceNumber, enc)
	return encDES(token, next)
}
