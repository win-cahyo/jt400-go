package as400

import (
	"reflect"
	"testing"
)

func TestEncodeDecodeParamsRoundTrip(t *testing.T) {
	params := []Param{
		{CodePoint: 0x1101, Data: []byte{0x00, 0x00, 0x00, 0x01}},
		{CodePoint: 0x1103, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		{CodePoint: 0x111F, Data: nil},
	}
	encoded := EncodeParams(params...)

	decoded, err := DecodeParams(encoded)
	if err != nil {
		t.Fatalf("DecodeParams: %v", err)
	}
	if len(decoded) != len(params) {
		t.Fatalf("decoded %d params, want %d", len(decoded), len(params))
	}
	for i, p := range params {
		if decoded[i].CodePoint != p.CodePoint {
			t.Errorf("param %d: CodePoint = %#x, want %#x", i, decoded[i].CodePoint, p.CodePoint)
		}
		if !reflect.DeepEqual(decoded[i].Data, p.Data) && len(decoded[i].Data)+len(p.Data) != 0 {
			t.Errorf("param %d: Data = %v, want %v", i, decoded[i].Data, p.Data)
		}
	}

	if d, ok := Find(decoded, 0x1103); !ok || len(d) != 8 {
		t.Errorf("Find(0x1103) = (%v, %v), want an 8-byte match", d, ok)
	}
	if _, ok := Find(decoded, 0x9999); ok {
		t.Error("Find should not match an absent code point")
	}
}

func TestDecodeParamsRejectsTruncatedInput(t *testing.T) {
	if _, err := DecodeParams([]byte{0x00, 0x00, 0x00, 0xFF, 0x11, 0x01}); err == nil {
		t.Fatal("expected an error for a declared length exceeding the buffer")
	}
	if _, err := DecodeParams([]byte{0x01, 0x02, 0x03}); err == nil {
		t.Fatal("expected an error for a buffer shorter than one LL/CP header")
	}
}
