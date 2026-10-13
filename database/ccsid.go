package database

import (
	"fmt"
	"sync"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/unicode"
)

// Well-known CCSIDs this package treats specially.
const (
	ccsidEBCDIC37 = 37
	ccsidUTF16    = 1200
	ccsidUCS2     = 13488
	ccsidUTF8     = 1208
	ccsidBinary   = 65535

	// clientCCSID is the CCSID this client declares for SQL statement text
	// (DBSQLAttributesDS.setClientCCSID). JTOpen's default "package ccsid"
	// is 13488 (UCS-2), which keeps statement text independent of the
	// server job's EBCDIC code page.
	clientCCSID = ccsidUCS2
)

var (
	ccsidMu sync.RWMutex
	ccsids  = map[int]encoding.Encoding{
		37:          charmap.CodePage037,
		1047:        charmap.CodePage1047,
		1140:        charmap.CodePage1140,
		ccsidUTF16:  unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM),
		ccsidUCS2:   unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM),
		ccsidUTF8:   unicode.UTF8,
		ccsidBinary: encoding.Nop,
	}
)

// RegisterCCSID makes enc available for converting character data tagged
// with ccsid, replacing any built-in mapping. Call it before connecting;
// it is safe for concurrent use but has no effect on rows already decoded.
func RegisterCCSID(ccsid int, enc encoding.Encoding) {
	ccsidMu.Lock()
	defer ccsidMu.Unlock()
	ccsids[ccsid] = enc
}

func lookupCCSID(ccsid int) (encoding.Encoding, error) {
	ccsidMu.RLock()
	defer ccsidMu.RUnlock()
	enc, ok := ccsids[ccsid]
	if !ok {
		return nil, fmt.Errorf("database: no converter registered for CCSID %d (see RegisterCCSID)", ccsid)
	}
	return enc, nil
}

// encodeString converts s to ccsid's byte form. Characters ccsid cannot
// represent are an error, never silently substituted.
func encodeString(ccsid int, s string) ([]byte, error) {
	enc, err := lookupCCSID(ccsid)
	if err != nil {
		return nil, err
	}
	b, err := enc.NewEncoder().Bytes([]byte(s))
	if err != nil {
		return nil, fmt.Errorf("database: encode %q to CCSID %d: %w", s, ccsid, err)
	}
	return b, nil
}

func decodeString(ccsid int, b []byte) (string, error) {
	enc, err := lookupCCSID(ccsid)
	if err != nil {
		return "", err
	}
	s, err := enc.NewDecoder().Bytes(b)
	if err != nil {
		return "", fmt.Errorf("database: decode CCSID %d: %w", ccsid, err)
	}
	return string(s), nil
}

// blank returns ccsid's encoding of a single space, used to pad
// fixed-length character fields the way JTOpen's SQLChar does.
func blank(ccsid int) ([]byte, error) {
	return encodeString(ccsid, " ")
}

// decodeServerText decodes a server-generated informational field (message
// text, SQLSTATE, job name) tagged with ccsid, falling back to CCSID 37 —
// whose invariant characters cover every SQLSTATE and message ID — when
// that CCSID has no registered converter, rather than failing the request
// that carried it.
func decodeServerText(ccsid int, b []byte) string {
	if ccsid == 0 || ccsid == ccsidBinary {
		ccsid = ccsidEBCDIC37
	}
	if s, err := decodeString(ccsid, b); err == nil {
		return s
	}
	s, _ := decodeString(ccsidEBCDIC37, b)
	return s
}
