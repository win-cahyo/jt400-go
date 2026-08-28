package rmtcmd

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/win-cahyo/jt400-go/as400"
	"github.com/win-cahyo/jt400-go/as400/auth"
)

func TestBuildExchangeAttributesRequestLayout(t *testing.T) {
	req := buildExchangeAttributesRequest()
	if req.ReqRepID != 0x1001 || req.TemplateLen != 14 || len(req.Body) != 14 {
		t.Fatalf("unexpected request shape: %+v", req)
	}
	if got := binary.BigEndian.Uint32(req.Body[0:4]); got != 37 {
		t.Errorf("client CCSID = %d, want 37", got)
	}
	if got := binary.BigEndian.Uint32(req.Body[8:12]); got != 1 {
		t.Errorf("client version = %d, want 1", got)
	}
}

func TestParseExchangeAttributesReply(t *testing.T) {
	body := make([]byte, 16)
	binary.BigEndian.PutUint16(body[0:2], 0) // RC
	binary.BigEndian.PutUint32(body[2:6], 37)
	binary.BigEndian.PutUint16(body[14:16], 11)

	ccsid, dsLevel, err := parseExchangeAttributesReply(&as400.Reply{Body: body})
	if err != nil {
		t.Fatalf("parseExchangeAttributesReply: %v", err)
	}
	if ccsid != 37 || dsLevel != 11 {
		t.Errorf("ccsid=%d dsLevel=%d, want 37, 11", ccsid, dsLevel)
	}
}

func TestBuildRunCommandRequestRejectsOldDSLevel(t *testing.T) {
	if _, err := buildRunCommandRequest("WRKACTJOB", 7, MessageOptionNone); err == nil {
		t.Fatal("expected an error for a datastream level below 10")
	}
}

func TestBuildRunCommandRequestLayout(t *testing.T) {
	req, err := buildRunCommandRequest("WRKACTJOB", 11, MessageOptionAll)
	if err != nil {
		t.Fatal(err)
	}
	if req.ReqRepID != 0x1002 || req.TemplateLen != 1 {
		t.Fatalf("unexpected request shape: %+v", req)
	}
	if req.Body[0] != 6 { // dsLevel>=11: ALL -> 6
		t.Errorf("message option byte = %d, want 6", req.Body[0])
	}
	cmdBytes := auth.UTF16BE("WRKACTJOB")
	if got := binary.BigEndian.Uint32(req.Body[1:5]); got != uint32(10+len(cmdBytes)) {
		t.Errorf("LL = %d, want %d", got, 10+len(cmdBytes))
	}
	if got := binary.BigEndian.Uint16(req.Body[5:7]); got != 0x1104 {
		t.Errorf("CP = %#x, want 0x1104", got)
	}
	if got := binary.BigEndian.Uint32(req.Body[7:11]); got != 1200 {
		t.Errorf("command CCSID = %d, want 1200", got)
	}
	if !bytes.Equal(req.Body[11:], cmdBytes) {
		t.Error("command text mismatch")
	}
}

func TestRemapMessageCount(t *testing.T) {
	cases := []struct {
		dsLevel uint16
		opt     MessageOption
		want    byte
	}{
		{5, MessageOptionAll, 0}, // <7: ALL forced down to UP_TO_10=0
		{7, MessageOptionAll, 2}, // 7<=level<10: no remap
		{10, MessageOptionUpTo10, 3},
		{10, MessageOptionAll, 4},
		{11, MessageOptionUpTo10, 5},
		{11, MessageOptionAll, 6},
		{11, MessageOptionNone, 1},
	}
	for _, c := range cases {
		if got := remapMessageCount(c.dsLevel, c.opt); got != c.want {
			t.Errorf("remapMessageCount(%d, %d) = %d, want %d", c.dsLevel, c.opt, got, c.want)
		}
	}
}

func TestBuildCallProgramRequestLayout(t *testing.T) {
	params := []*Parameter{
		{Usage: Input, MaxLength: 5, InputData: []byte{1, 2, 3, 0, 0}}, // trailing zeros trimmed
		{Usage: Output, MaxLength: 10},
		{Usage: InOut, MaxLength: 8, InputData: []byte{9, 9, 9, 9, 9, 9, 9, 9}},
		{Usage: Null, MaxLength: 4},
	}
	req, err := buildCallProgramRequest("MYLIB", "MYPGM", params, 11, MessageOptionNone)
	if err != nil {
		t.Fatal(err)
	}
	if req.ReqRepID != 0x1003 || req.TemplateLen != 23 {
		t.Fatalf("unexpected request shape: %+v", req)
	}
	if !bytes.Equal(req.Body[0:10], mustEBCDIC(t, "MYPGM")) {
		t.Error("program name mismatch")
	}
	if !bytes.Equal(req.Body[10:20], mustEBCDIC(t, "MYLIB")) {
		t.Error("library name mismatch")
	}
	if got := binary.BigEndian.Uint16(req.Body[21:23]); got != 4 {
		t.Errorf("param count = %d, want 4", got)
	}

	idx := 23
	// param 0: Input, trimmed to 3 bytes -> LL=15, usage=11
	if got := binary.BigEndian.Uint32(req.Body[idx : idx+4]); got != 15 {
		t.Errorf("param0 LL = %d, want 15", got)
	}
	if got := binary.BigEndian.Uint16(req.Body[idx+10 : idx+12]); got != 11 {
		t.Errorf("param0 usage = %d, want 11", got)
	}
	if !bytes.Equal(req.Body[idx+12:idx+15], []byte{1, 2, 3}) {
		t.Errorf("param0 data = %v, want [1 2 3]", req.Body[idx+12:idx+15])
	}
	idx += 15

	// param 1: Output, no data -> LL=12, usage=22
	if got := binary.BigEndian.Uint32(req.Body[idx : idx+4]); got != 12 {
		t.Errorf("param1 LL = %d, want 12", got)
	}
	if got := binary.BigEndian.Uint16(req.Body[idx+10 : idx+12]); got != 22 {
		t.Errorf("param1 usage = %d, want 22", got)
	}
	idx += 12

	// param 2: InOut, dsLevel>=5 -> usage=33, 8 bytes data -> LL=20
	if got := binary.BigEndian.Uint32(req.Body[idx : idx+4]); got != 20 {
		t.Errorf("param2 LL = %d, want 20", got)
	}
	if got := binary.BigEndian.Uint16(req.Body[idx+10 : idx+12]); got != 33 {
		t.Errorf("param2 usage = %d, want 33", got)
	}
	idx += 20

	// param 3: Null, dsLevel>=6 -> usage=0xFF, no data -> LL=12
	if got := binary.BigEndian.Uint32(req.Body[idx : idx+4]); got != 12 {
		t.Errorf("param3 LL = %d, want 12", got)
	}
	if got := binary.BigEndian.Uint16(req.Body[idx+10 : idx+12]); got != 0xFF {
		t.Errorf("param3 usage = %#x, want 0xFF", got)
	}
	idx += 12

	if idx != len(req.Body) {
		t.Errorf("consumed %d bytes, body is %d bytes", idx, len(req.Body))
	}
}

// buildOutputEntry builds one parameter entry as parseCallProgramOutput
// expects it: length(4)+code(2, unused here)+declaredLength(4)+usage(2)+data.
func buildOutputEntry(usage uint16, declaredLength uint32, data []byte) []byte {
	entry := make([]byte, 12+len(data))
	binary.BigEndian.PutUint32(entry[0:4], uint32(len(entry)))
	binary.BigEndian.PutUint32(entry[6:10], declaredLength)
	binary.BigEndian.PutUint16(entry[10:12], usage)
	copy(entry[12:], data)
	return entry
}

func TestParseCallProgramOutput(t *testing.T) {
	t.Run("plain (uncompressed) output data", func(t *testing.T) {
		body := make([]byte, 4)
		body = append(body, buildOutputEntry(0, 5, []byte("HELLO"))...)

		params := []*Parameter{{Usage: Output, MaxLength: 30000}}
		if err := parseCallProgramOutput(body, params); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(params[0].OutputData, []byte("HELLO")) {
			t.Errorf("OutputData = %q, want %q", params[0].OutputData, "HELLO")
		}
	})

	t.Run("RLE-compressed output data is decompressed", func(t *testing.T) {
		// "AB" followed by the pair (0x40,0x40) repeated 3 times: declared
		// (decompressed) length is 2+6=8, wire data is 2+5=7 bytes.
		compressed := append([]byte("AB"), rleEscape, 0x40, 0x40, 0x00, 0x03)
		body := make([]byte, 4)
		body = append(body, buildOutputEntry(22, 8, compressed)...)

		params := []*Parameter{{Usage: Output, MaxLength: 30000}}
		if err := parseCallProgramOutput(body, params); err != nil {
			t.Fatal(err)
		}
		want := append([]byte("AB"), 0x40, 0x40, 0x40, 0x40, 0x40, 0x40)
		if !bytes.Equal(params[0].OutputData, want) {
			t.Errorf("OutputData = %v, want %v", params[0].OutputData, want)
		}
	})

	t.Run("multiple parameters, only Output/InOut ones consumed", func(t *testing.T) {
		body := make([]byte, 4)
		body = append(body, buildOutputEntry(0, 3, []byte("ABC"))...)
		body = append(body, buildOutputEntry(0, 2, []byte("XY"))...)

		params := []*Parameter{
			{Usage: Input, MaxLength: 10}, // skipped: not Output/InOut, no entry in body for it
			{Usage: Output, MaxLength: 30000},
			{Usage: InOut, MaxLength: 30000},
		}
		if err := parseCallProgramOutput(body, params); err != nil {
			t.Fatal(err)
		}
		if params[0].OutputData != nil {
			t.Errorf("Input param OutputData = %v, want nil", params[0].OutputData)
		}
		if !bytes.Equal(params[1].OutputData, []byte("ABC")) {
			t.Errorf("param1 OutputData = %q, want %q", params[1].OutputData, "ABC")
		}
		if !bytes.Equal(params[2].OutputData, []byte("XY")) {
			t.Errorf("param2 OutputData = %q, want %q", params[2].OutputData, "XY")
		}
	})
}

func mustEBCDIC(t *testing.T, s string) []byte {
	t.Helper()
	b, err := auth.EncodeEBCDICPadded(s, 10)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
