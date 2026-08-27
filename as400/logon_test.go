package as400

import (
	"encoding/binary"
	"testing"

	"jt400-go/as400/auth"
)

func TestBuildXChgRandSeedRequestShape(t *testing.T) {
	seed := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	req := buildXChgRandSeedRequest(ServerDataQueue, seed)
	if req.ReqRepID != 0x7001 {
		t.Errorf("ReqRepID = %#x, want 0x7001", req.ReqRepID)
	}
	if req.HeaderID>>8 != 0x03 {
		t.Errorf("client attrs byte = %#x, want 0x03", req.HeaderID>>8)
	}
	if req.TemplateLen != 8 {
		t.Errorf("TemplateLen = %d, want 8", req.TemplateLen)
	}
	encoded := req.Encode()
	if len(encoded) != 28 {
		t.Errorf("encoded length = %d, want 28", len(encoded))
	}
}

func TestParseXChgRandSeedReplyReadsSeedAndPasswordLevel(t *testing.T) {
	body := make([]byte, 12)
	binary.BigEndian.PutUint32(body[0:4], 0) // RC = 0
	serverSeed := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	copy(body[4:12], serverSeed)

	reply := &Reply{HeaderID: 0x0003, Body: body} // server attrs byte (low byte of HeaderID) = 3
	seed, level, err := parseXChgRandSeedReply(reply)
	if err != nil {
		t.Fatalf("parseXChgRandSeedReply: %v", err)
	}
	if seed != [8]byte{9, 8, 7, 6, 5, 4, 3, 2} {
		t.Errorf("serverSeed = %v, want %v", seed, serverSeed)
	}
	if level != 3 {
		t.Errorf("passwordLevel = %d, want 3", level)
	}
}

func TestBuildStartServerRequestShape(t *testing.T) {
	userID, err := auth.EncodeEBCDIC10("QUSER1")
	if err != nil {
		t.Fatal(err)
	}
	auth20 := make([]byte, 20) // SHA-1-length auth bytes
	req := buildStartServerRequest(ServerRemoteCommand, userID, auth20)
	if req.ReqRepID != 0x7002 {
		t.Errorf("ReqRepID = %#x, want 0x7002", req.ReqRepID)
	}
	if req.HeaderID>>8 != 0x02 {
		t.Errorf("client attrs byte = %#x, want 0x02", req.HeaderID>>8)
	}
	if req.Body[0] != 0x03 {
		t.Errorf("auth type byte = %#x, want 0x03 for a 20-byte auth value", req.Body[0])
	}
	if req.Body[1] != 0x01 {
		t.Errorf("send-reply byte = %#x, want 0x01", req.Body[1])
	}
	wantLen := 2 + (6 + 20) + (6 + 10)
	if len(req.Body) != wantLen {
		t.Errorf("body length = %d, want %d", len(req.Body), wantLen)
	}
}

func TestParseStartServerReplyDecodesJobNamePastCCSID(t *testing.T) {
	jobName, err := auth.EncodeEBCDIC10("QZRCSRVS")
	if err != nil {
		t.Fatal(err)
	}
	entry := make([]byte, 10+10)
	binary.BigEndian.PutUint32(entry[0:4], uint32(len(entry)))
	binary.BigEndian.PutUint16(entry[4:6], 0x111F)
	binary.BigEndian.PutUint32(entry[6:10], 37) // CCSID
	copy(entry[10:], jobName[:])

	body := make([]byte, 4) // RC = 0
	body = append(body, entry...)

	got, err := parseStartServerReply(&Reply{Body: body})
	if err != nil {
		t.Fatalf("parseStartServerReply: %v", err)
	}
	if got != "QZRCSRVS" {
		t.Errorf("jobName = %q, want %q", got, "QZRCSRVS")
	}
}
