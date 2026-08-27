package as400

import (
	"encoding/binary"
	"fmt"
)

// Param is one LL/CP encoded field: a self-describing chunk consisting of a
// 4-byte length (covering the length field itself, the code point, and the
// data), a 2-byte code point, and the data itself. This is the encoding
// used throughout the as-signon and as-dtaq wire protocols for optional and
// variable-length fields.
type Param struct {
	CodePoint uint16
	Data      []byte
}

// EncodeParams concatenates params into their LL/CP wire form.
func EncodeParams(params ...Param) []byte {
	var buf []byte
	for _, p := range params {
		entry := make([]byte, 6+len(p.Data))
		binary.BigEndian.PutUint32(entry[0:4], uint32(len(entry)))
		binary.BigEndian.PutUint16(entry[4:6], p.CodePoint)
		copy(entry[6:], p.Data)
		buf = append(buf, entry...)
	}
	return buf
}

// DecodeParams walks a byte slice of concatenated LL/CP entries, as found
// (starting at a service-specific offset) in host-server reply bodies.
func DecodeParams(b []byte) ([]Param, error) {
	var params []Param
	offset := 0
	for offset < len(b) {
		if offset+6 > len(b) {
			return nil, fmt.Errorf("as400: truncated parameter at offset %d", offset)
		}
		ll := binary.BigEndian.Uint32(b[offset : offset+4])
		if ll < 6 || offset+int(ll) > len(b) {
			return nil, fmt.Errorf("as400: invalid parameter length %d at offset %d", ll, offset)
		}
		cp := binary.BigEndian.Uint16(b[offset+4 : offset+6])
		data := b[offset+6 : offset+int(ll)]
		params = append(params, Param{CodePoint: cp, Data: data})
		offset += int(ll)
	}
	return params, nil
}

// Find returns the data of the first param with the given code point.
func Find(params []Param, cp uint16) ([]byte, bool) {
	for _, p := range params {
		if p.CodePoint == cp {
			return p.Data, true
		}
	}
	return nil, false
}
