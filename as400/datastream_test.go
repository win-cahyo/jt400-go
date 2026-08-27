package as400

import (
	"bytes"
	"testing"
)

func TestRequestEncodeReadReplyRoundTrip(t *testing.T) {
	req := Request{
		ServerID:    ServerSignon,
		Correlation: 42,
		TemplateLen: 3,
		ReqRepID:    0x7003,
		Body:        []byte{0x01, 0x02, 0x03, 0xAA, 0xBB},
	}
	encoded := req.Encode()

	if got, want := len(encoded), HeaderLength+len(req.Body); got != want {
		t.Fatalf("encoded length = %d, want %d", got, want)
	}

	reply, err := ReadReply(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("ReadReply: %v", err)
	}
	if reply.ServerID != req.ServerID {
		t.Errorf("ServerID = %#x, want %#x", reply.ServerID, req.ServerID)
	}
	if reply.Correlation != req.Correlation {
		t.Errorf("Correlation = %d, want %d", reply.Correlation, req.Correlation)
	}
	if reply.TemplateLen != req.TemplateLen {
		t.Errorf("TemplateLen = %d, want %d", reply.TemplateLen, req.TemplateLen)
	}
	if reply.ReqRepID != req.ReqRepID {
		t.Errorf("ReqRepID = %#x, want %#x", reply.ReqRepID, req.ReqRepID)
	}
	if !bytes.Equal(reply.Body, req.Body) {
		t.Errorf("Body = %v, want %v", reply.Body, req.Body)
	}
}

func TestReadReplyRejectsBadServerID(t *testing.T) {
	buf := make([]byte, HeaderLength)
	buf[0], buf[1], buf[2], buf[3] = 0, 0, 0, HeaderLength
	buf[6] = 0xAB // not 0xE0
	if _, err := ReadReply(bytes.NewReader(buf)); err == nil {
		t.Fatal("expected an error for a non-0xE0xx server id")
	}
}

func TestRC(t *testing.T) {
	r := &Reply{Body: []byte{0x00, 0x00, 0x00, 0x2A, 0xFF}}
	rc, ok := r.RC()
	if !ok || rc != 42 {
		t.Fatalf("RC() = (%d, %v), want (42, true)", rc, ok)
	}
	empty := &Reply{Body: []byte{0x01, 0x02}}
	if _, ok := empty.RC(); ok {
		t.Fatal("RC() should report false for a body shorter than 4 bytes")
	}
}
