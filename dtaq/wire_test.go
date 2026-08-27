package dtaq

import (
	"bytes"
	"encoding/binary"
	"testing"

	"jt400-go/as400"
	"jt400-go/as400/auth"
)

func mustEBCDIC(t *testing.T, s string, n int) []byte {
	t.Helper()
	b, err := auth.EncodeEBCDICPadded(s, n)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBuildCreateRequestLayout(t *testing.T) {
	req, err := buildCreateRequest("MYLIB", "MYQ", CreateOptions{
		MaxEntryLength:  100,
		PublicAuthority: AuthorityChange,
		Keyed:           true,
		KeyLength:       4,
		TextDescription: "TEST QUEUE",
	})
	if err != nil {
		t.Fatal(err)
	}
	if req.ReqRepID != 0x0003 || req.TemplateLen != 80 || req.ServerID != as400.ServerDataQueue {
		t.Fatalf("unexpected request shape: %+v", req)
	}
	if len(req.Body) != 80 {
		t.Fatalf("body length = %d, want 80", len(req.Body))
	}
	if !bytes.Equal(req.Body[0:10], mustEBCDIC(t, "MYQ", 10)) {
		t.Error("queue name mismatch")
	}
	if !bytes.Equal(req.Body[10:20], mustEBCDIC(t, "MYLIB", 10)) {
		t.Error("library name mismatch")
	}
	if got := binary.BigEndian.Uint32(req.Body[20:24]); got != 100 {
		t.Errorf("max entry length = %d, want 100", got)
	}
	if req.Body[24] != byte(AuthorityChange) {
		t.Errorf("public authority = %#x, want %#x", req.Body[24], AuthorityChange)
	}
	if req.Body[26] != 0xF2 {
		t.Errorf("queue type = %#x, want 0xF2 (keyed)", req.Body[26])
	}
	if got := binary.BigEndian.Uint16(req.Body[27:29]); got != 4 {
		t.Errorf("key length = %d, want 4", got)
	}
	if !bytes.Equal(req.Body[30:80], mustEBCDIC(t, "TEST QUEUE", 50)) {
		t.Error("text description mismatch")
	}
}

func TestBuildCreateRequestNonKeyedClearsKeyLength(t *testing.T) {
	req, err := buildCreateRequest("LIB", "Q", CreateOptions{Keyed: false, FIFO: true, KeyLength: 99})
	if err != nil {
		t.Fatal(err)
	}
	if req.Body[26] != 0xF0 {
		t.Errorf("queue type = %#x, want 0xF0 (FIFO)", req.Body[26])
	}
	if got := binary.BigEndian.Uint16(req.Body[27:29]); got != 0 {
		t.Errorf("key length = %d, want 0 for a non-keyed queue even though KeyLength was set", got)
	}
}

func TestBuildDeleteRequestLayout(t *testing.T) {
	req, err := buildQueueOnlyRequest(0x0004, "LIB1", "Q1")
	if err != nil {
		t.Fatal(err)
	}
	if req.ReqRepID != 0x0004 || req.TemplateLen != 20 || len(req.Body) != 20 {
		t.Fatalf("unexpected request shape: %+v", req)
	}
}

func TestBuildClearRequestLayout(t *testing.T) {
	req, err := buildClearRequest("LIB", "Q", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if req.ReqRepID != 0x0006 || req.TemplateLen != 21 || len(req.Body) != 21 {
		t.Fatalf("unexpected non-keyed clear shape: %+v", req)
	}
	if req.Body[20] != 0xF0 {
		t.Errorf("hasKey flag = %#x, want 0xF0", req.Body[20])
	}

	keyed, err := buildClearRequest("LIB", "Q", []byte{0xAA, 0xBB}, true)
	if err != nil {
		t.Fatal(err)
	}
	wantLen := 21 + 6 + 2
	if len(keyed.Body) != wantLen {
		t.Fatalf("keyed clear body length = %d, want %d", len(keyed.Body), wantLen)
	}
	if keyed.Body[20] != 0xF1 {
		t.Errorf("hasKey flag = %#x, want 0xF1", keyed.Body[20])
	}
	params, err := as400.DecodeParams(keyed.Body[21:])
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := as400.Find(params, 0x5002); !ok || !bytes.Equal(d, []byte{0xAA, 0xBB}) {
		t.Errorf("key param = %v, ok=%v, want [0xAA 0xBB], true", d, ok)
	}
}

func TestBuildWriteRequestLayout(t *testing.T) {
	req, err := buildWriteRequest("LIB", "Q", nil, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if req.ReqRepID != 0x0005 || req.TemplateLen != 22 {
		t.Fatalf("unexpected request shape: %+v", req)
	}
	if req.Body[20] != 0xF0 {
		t.Errorf("hasKey = %#x, want 0xF0", req.Body[20])
	}
	params, err := as400.DecodeParams(req.Body[22:])
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := as400.Find(params, 0x5001); !ok || string(d) != "hello" {
		t.Errorf("entry data = %q, ok=%v, want %q, true", d, ok, "hello")
	}

	keyed, err := buildWriteRequest("LIB", "Q", []byte{1, 2, 3}, []byte("world"))
	if err != nil {
		t.Fatal(err)
	}
	if keyed.Body[20] != 0xF1 {
		t.Errorf("hasKey = %#x, want 0xF1", keyed.Body[20])
	}
	params, err = as400.DecodeParams(keyed.Body[22:])
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := as400.Find(params, 0x5002); !ok || !bytes.Equal(d, []byte{1, 2, 3}) {
		t.Errorf("key data = %v, ok=%v, want [1 2 3], true", d, ok)
	}
}

func TestBuildReadRequestLayout(t *testing.T) {
	req, err := buildReadRequest("LIB", "Q", false, "", nil, -1, true)
	if err != nil {
		t.Fatal(err)
	}
	if req.ReqRepID != 0x0002 || req.TemplateLen != 28 || len(req.Body) != 28 {
		t.Fatalf("unexpected non-keyed read shape: %+v", req)
	}
	if req.Body[20] != 0xF0 {
		t.Errorf("hasKey = %#x, want 0xF0", req.Body[20])
	}
	if got := int32(binary.BigEndian.Uint32(req.Body[23:27])); got != -1 {
		t.Errorf("wait seconds = %d, want -1", got)
	}
	if req.Body[27] != 0xF1 {
		t.Errorf("peek flag = %#x, want 0xF1", req.Body[27])
	}

	keyed, err := buildReadRequest("LIB", "Q", true, SearchEQ, []byte{9, 9}, 5, false)
	if err != nil {
		t.Fatal(err)
	}
	if keyed.Body[20] != 0xF1 {
		t.Errorf("hasKey = %#x, want 0xF1", keyed.Body[20])
	}
	if !bytes.Equal(keyed.Body[21:23], mustEBCDIC(t, "EQ", 2)) {
		t.Error("search type mismatch")
	}
	if keyed.Body[27] != 0xF0 {
		t.Errorf("peek flag = %#x, want 0xF0 (destructive read)", keyed.Body[27])
	}
	params, err := as400.DecodeParams(keyed.Body[28:])
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := as400.Find(params, 0x5002); !ok || !bytes.Equal(d, []byte{9, 9}) {
		t.Errorf("search key = %v, ok=%v, want [9 9], true", d, ok)
	}
}

func TestCheckCommonReplySuccess(t *testing.T) {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, 0xF000)
	if err := checkCommonReply(&as400.Reply{Body: body}); err != nil {
		t.Errorf("checkCommonReply(RC=0xF000) = %v, want nil", err)
	}
}

func TestCheckCommonReplyWithMessage(t *testing.T) {
	msgID := mustEBCDIC(t, "CPF9870", 7)
	msgText, err := auth.EncodeEBCDIC("OBJECT ALREADY EXISTS")
	if err != nil {
		t.Fatal(err)
	}
	msg := append(append(append([]byte{}, msgID...), 0x40, 0x40), msgText...)

	body := make([]byte, 2, 2+6+len(msg))
	binary.BigEndian.PutUint16(body[0:2], 0xF001)
	ll := make([]byte, 4)
	binary.BigEndian.PutUint32(ll, uint32(6+len(msg)))
	body = append(body, ll...)
	body = append(body, 0x00, 0x00) // CP, unread by client code
	body = append(body, msg...)

	err = checkCommonReply(&as400.Reply{Body: body})
	dtaqErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("checkCommonReply returned %T, want *Error", err)
	}
	if dtaqErr.RC != 0xF001 {
		t.Errorf("RC = %#x, want 0xF001", dtaqErr.RC)
	}
	if dtaqErr.MessageID != "CPF9870" {
		t.Errorf("MessageID = %q, want %q", dtaqErr.MessageID, "CPF9870")
	}
	if dtaqErr.Message != "OBJECT ALREADY EXISTS" {
		t.Errorf("Message = %q, want %q", dtaqErr.Message, "OBJECT ALREADY EXISTS")
	}
}

func TestParseReadReplySuccess(t *testing.T) {
	entryBody := []byte("payload")
	keyBody := []byte{7, 7}

	body := make([]byte, 38)
	body[0], body[1] = 0, 0
	sender := body[2:38]
	for i := range sender {
		sender[i] = 0x40 // blank: no sender info saved
	}
	body = append(body, as400.EncodeParams(
		as400.Param{CodePoint: 0x5001, Data: entryBody},
		as400.Param{CodePoint: 0x5002, Data: keyBody},
	)...)

	entry, err := parseReadReply(&as400.Reply{ReqRepID: 0x8003, Body: body})
	if err != nil {
		t.Fatalf("parseReadReply: %v", err)
	}
	if entry == nil {
		t.Fatal("entry is nil")
	}
	if !bytes.Equal(entry.Data, entryBody) {
		t.Errorf("Data = %v, want %v", entry.Data, entryBody)
	}
	if !bytes.Equal(entry.Key, keyBody) {
		t.Errorf("Key = %v, want %v", entry.Key, keyBody)
	}
	if entry.SenderInformation != nil {
		t.Errorf("SenderInformation = %v, want nil (all-blank sentinel)", entry.SenderInformation)
	}
}

func TestParseReadReplyNoData(t *testing.T) {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, 0xF006)
	entry, err := parseReadReply(&as400.Reply{ReqRepID: 0x8002, Body: body})
	if err != nil {
		t.Fatalf("parseReadReply: %v", err)
	}
	if entry != nil {
		t.Errorf("entry = %+v, want nil for RC=0xF006", entry)
	}
}

func TestParseAttributesReply(t *testing.T) {
	text := mustEBCDIC(t, "MY QUEUE", 50)
	body := make([]byte, 61)
	binary.BigEndian.PutUint32(body[2:6], 12345)
	body[6] = 0xF1 // save sender info
	body[7] = 0x02 // keyed (low nibble)
	binary.BigEndian.PutUint16(body[8:10], 4)
	body[10] = 0xF0 // not forced to aux storage
	copy(body[11:61], text)

	attrs, err := parseAttributesReply(&as400.Reply{ReqRepID: 0x8001, Body: body})
	if err != nil {
		t.Fatalf("parseAttributesReply: %v", err)
	}
	if attrs.MaxEntryLength != 12345 {
		t.Errorf("MaxEntryLength = %d, want 12345", attrs.MaxEntryLength)
	}
	if !attrs.SaveSenderInformation {
		t.Error("SaveSenderInformation = false, want true")
	}
	if !attrs.Keyed {
		t.Error("Keyed = false, want true")
	}
	if attrs.KeyLength != 4 {
		t.Errorf("KeyLength = %d, want 4", attrs.KeyLength)
	}
	if attrs.TextDescription != "MY QUEUE" {
		t.Errorf("TextDescription = %q, want %q", attrs.TextDescription, "MY QUEUE")
	}
}
