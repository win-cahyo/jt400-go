package signon

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/win-cahyo/jt400-go/as400"
	"github.com/win-cahyo/jt400-go/as400/auth"
)

func be32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func be16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

// exchangeAttributes holds the fields negotiated by the exchange-attributes
// handshake (SignonExchangeAttributeReq/Rep, opcode 0x7003 / reply 0xF003).
type exchangeAttributes struct {
	ServerVersion uint32
	ServerLevel   uint16
	ServerSeed    [8]byte
	PasswordLevel PasswordLevel
	JobName       string
	AAFIndicator  bool
}

// buildExchangeAttributeRequest builds the client->server datastream that
// starts every as-signon session. Client datastream level is sent as 0
// (the value JTOpen sends when targeting as-signon rather than as-hostcnn)
// — the server negotiates the actual password scheme independently via the
// password-level field in the reply.
func buildExchangeAttributeRequest(clientSeed [8]byte) as400.Request {
	body := as400.EncodeParams(
		as400.Param{CodePoint: 0x1101, Data: be32(1)}, // client version
		as400.Param{CodePoint: 0x1102, Data: be16(0)}, // client datastream level
		as400.Param{CodePoint: 0x1103, Data: clientSeed[:]},
	)
	return as400.Request{
		ServerID: as400.ServerSignon,
		ReqRepID: 0x7003,
		Body:     body,
	}
}

func parseExchangeAttributeReply(reply *as400.Reply) (*exchangeAttributes, error) {
	rc, ok := reply.RC()
	if !ok {
		return nil, fmt.Errorf("signon: exchange-attributes reply too short")
	}
	if rc != 0 {
		return nil, fmt.Errorf("signon: exchange attributes failed, rc=%#08x", rc)
	}
	if len(reply.Body) < 22 {
		return nil, fmt.Errorf("signon: exchange-attributes reply missing fixed fields")
	}
	attrs := &exchangeAttributes{
		ServerVersion: binary.BigEndian.Uint32(reply.Body[10:14]),
		ServerLevel:   binary.BigEndian.Uint16(reply.Body[20:22]),
	}
	params, err := as400.DecodeParams(reply.Body[22:])
	if err != nil {
		return nil, fmt.Errorf("signon: decode exchange-attributes reply: %w", err)
	}
	if d, ok := as400.Find(params, 0x1103); ok && len(d) >= 8 {
		copy(attrs.ServerSeed[:], d[:8])
	}
	if d, ok := as400.Find(params, 0x1119); ok && len(d) >= 1 {
		attrs.PasswordLevel = auth.PasswordLevel(d[0])
	}
	// CP 0x111F (job name) carries a 4-byte CCSID between the CP and the
	// text — a 10-byte entry header, not the plain 6-byte LL/CP header
	// most fields use (confirmed against SignonExchangeAttributeRep.
	// getJobNameBytes(), which reads the name at offset+10 with length
	// LL-10) — so the first 4 bytes of Data here are that CCSID, not text.
	if d, ok := as400.Find(params, 0x111F); ok && len(d) >= 4 {
		attrs.JobName = strings.TrimRight(auth.DecodeEBCDICLossy(d[4:]), " ")
	}
	if d, ok := as400.Find(params, 0x112E); ok && len(d) >= 1 {
		attrs.AAFIndicator = d[0] == 0x01
	}
	return attrs, nil
}

// buildSignonInfoRequest builds the SignonInfoReq datastream (opcode
// 0x7004) that carries the encrypted authentication bytes.
func buildSignonInfoRequest(userIDBytes [10]byte, authBytes []byte, serverLevel uint16) as400.Request {
	var authType byte
	switch len(authBytes) {
	case 8:
		authType = 0x01 // DES password substitute
	case 20:
		authType = 0x03 // SHA-1 password substitute
	default:
		authType = 0x07 // SHA-512 password substitute
	}

	body := []byte{authType}
	body = append(body, as400.EncodeParams(as400.Param{CodePoint: 0x1113, Data: be32(1200)})...) // client CCSID (Unicode)
	body = append(body, as400.EncodeParams(as400.Param{CodePoint: 0x1105, Data: authBytes})...)  // password scheme auth data
	body = append(body, as400.EncodeParams(as400.Param{CodePoint: 0x1104, Data: userIDBytes[:]})...)
	if serverLevel >= 5 {
		body = append(body, as400.EncodeParams(as400.Param{CodePoint: 0x1128, Data: []byte{0x01}})...) // return error messages
	}

	return as400.Request{
		ServerID:    as400.ServerSignon,
		ReqRepID:    0x7004,
		TemplateLen: 1,
		Body:        body,
	}
}

// SignonInfo is the information returned by a successful Authenticate call.
type SignonInfo struct {
	CurrentSignonDate             time.Time
	LastSignonDate                time.Time
	ExpirationDate                time.Time
	PasswordExpirationWarningDays int32
	ServerCCSID                   uint32
	// UserID is the server-returned user ID, present even when the caller
	// authenticated with something other than a plain user ID (e.g. a
	// blank ID paired with a profile token — not currently supported by
	// this library, but the field is decoded regardless).
	UserID string
}

func parseSignonInfoReply(reply *as400.Reply) (*SignonInfo, error) {
	rc, ok := reply.RC()
	if !ok {
		return nil, fmt.Errorf("signon: reply too short to contain a return code")
	}
	if rc != 0 {
		return nil, signonError(rc)
	}
	if len(reply.Body) < 4 {
		return nil, fmt.Errorf("signon: reply missing parameter section")
	}
	params, err := as400.DecodeParams(reply.Body[4:])
	if err != nil {
		return nil, fmt.Errorf("signon: decode signon info reply: %w", err)
	}

	info := &SignonInfo{}
	if d, ok := as400.Find(params, 0x1106); ok {
		if t, err := parseSignonDate(d); err == nil {
			info.CurrentSignonDate = t
		}
	}
	if d, ok := as400.Find(params, 0x1107); ok {
		if t, err := parseSignonDate(d); err == nil {
			info.LastSignonDate = t
		}
	}
	if d, ok := as400.Find(params, 0x1108); ok {
		if t, err := parseSignonDate(d); err == nil {
			info.ExpirationDate = t
		}
	}
	if d, ok := as400.Find(params, 0x1114); ok && len(d) >= 4 {
		info.ServerCCSID = binary.BigEndian.Uint32(d)
	}
	// CP 0x1104 (returned user ID) also carries a 4-byte CCSID header
	// before the 10-byte EBCDIC ID (see SignonInfoRep.getUserIdBytes(),
	// which copies from offset+10) — same convention as job name above.
	if d, ok := as400.Find(params, 0x1104); ok && len(d) >= 14 {
		var u [10]byte
		copy(u[:], d[4:14])
		info.UserID = strings.TrimRight(auth.DecodeEBCDIC10(u), " ")
	}
	if d, ok := as400.Find(params, 0x112C); ok && len(d) >= 4 {
		info.PasswordExpirationWarningDays = int32(binary.BigEndian.Uint32(d))
	}
	return info, nil
}

// parseSignonDate decodes the 7-byte date/time layout used by CP
// 0x1106/0x1107/0x1108: 2-byte year, then single bytes for month (1-based,
// same convention as time.Month — no adjustment needed going into Go, in
// contrast to Java's 0-based java.util.Calendar.MONTH which is why the
// JTOpen source subtracts 1), day, hour, minute, second.
func parseSignonDate(data []byte) (time.Time, error) {
	if len(data) < 7 {
		return time.Time{}, fmt.Errorf("date field too short")
	}
	year := int(binary.BigEndian.Uint16(data[0:2]))
	month := time.Month(data[2])
	day := int(data[3])
	hour := int(data[4])
	minute := int(data[5])
	sec := int(data[6])
	return time.Date(year, month, day, hour, minute, sec, 0, time.UTC), nil
}
