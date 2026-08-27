package signon

import (
	"encoding/binary"
	"testing"

	"github.com/win-cahyo/jt400-go/as400"
	"github.com/win-cahyo/jt400-go/as400/auth"
)

// ccsidTextEntry builds an LL/CP entry using the 10-byte header (LL+CP+CCSID)
// convention that CP 0x111F (job name) and CP 0x1104 (returned user ID) use
// on their reply datastreams — distinct from the plain 6-byte LL/CP header
// as400.EncodeParams produces, which is why these two fields need their own
// helper rather than as400.Param.
func ccsidTextEntry(cp uint16, ccsid uint32, text []byte) []byte {
	entry := make([]byte, 10+len(text))
	binary.BigEndian.PutUint32(entry[0:4], uint32(len(entry)))
	binary.BigEndian.PutUint16(entry[4:6], cp)
	binary.BigEndian.PutUint32(entry[6:10], ccsid)
	copy(entry[10:], text)
	return entry
}

func TestParseExchangeAttributeReplyDecodesJobNamePastCCSID(t *testing.T) {
	jobName, err := auth.EncodeEBCDIC10("QZDASOINIT")
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 22)
	binary.BigEndian.PutUint16(body[20:22], 5) // server datastream level
	body = append(body, ccsidTextEntry(0x111F, 37, jobName[:])...)

	reply := &as400.Reply{Body: body}
	attrs, err := parseExchangeAttributeReply(reply)
	if err != nil {
		t.Fatalf("parseExchangeAttributeReply: %v", err)
	}
	if attrs.JobName != "QZDASOINIT" {
		t.Errorf("JobName = %q, want %q (a CCSID-prefix parsing bug would prepend 4 garbage characters)", attrs.JobName, "QZDASOINIT")
	}
}

func TestParseSignonInfoReplyDecodesUserIDPastCCSID(t *testing.T) {
	userID, err := auth.EncodeEBCDIC10("QSECOFR")
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 4) // RC = 0
	body = append(body, ccsidTextEntry(0x1104, 37, userID[:])...)

	reply := &as400.Reply{Body: body}
	info, err := parseSignonInfoReply(reply)
	if err != nil {
		t.Fatalf("parseSignonInfoReply: %v", err)
	}
	if info.UserID != "QSECOFR" {
		t.Errorf("UserID = %q, want %q (a CCSID-prefix parsing bug would corrupt/truncate this)", info.UserID, "QSECOFR")
	}
}
