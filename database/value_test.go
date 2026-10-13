package database

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
	"time"
)

func TestDecodePacked(t *testing.T) {
	tests := []struct {
		name             string
		raw              []byte
		precision, scale int
		want             string
	}{
		{"positive with scale", []byte{0x12, 0x34, 0x5C}, 5, 2, "123.45"},
		{"negative no scale", []byte{0x00, 0x12, 0x3D}, 5, 0, "-123"},
		{"even precision has pad nibble", []byte{0x01, 0x23, 0x4F}, 4, 1, "123.4"},
		{"F sign is positive", []byte{0x00, 0x00, 0x5F}, 5, 2, "0.05"},
		{"negative zero prints as zero", []byte{0x00, 0x00, 0x0D}, 5, 2, "0.00"},
		{"B sign is negative", []byte{0x00, 0x10, 0x0B}, 5, 2, "-1.00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodePacked(tt.raw, tt.precision, tt.scale)
			if err != nil {
				t.Fatalf("decodePacked: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodePackedRejectsBadInput(t *testing.T) {
	if _, err := decodePacked([]byte{0x12, 0x3C}, 5, 0); err == nil {
		t.Error("expected length error")
	}
	if _, err := decodePacked([]byte{0xA2, 0x34, 0x5C}, 5, 0); err == nil {
		t.Error("expected invalid digit error")
	}
}

func TestDecodeZoned(t *testing.T) {
	got, err := decodeZoned([]byte{0xF0, 0xF1, 0xF2, 0xD3}, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got != "-1.23" {
		t.Errorf("got %q, want -1.23", got)
	}
	got, err = decodeZoned([]byte{0xF9, 0xF9}, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got != "99" {
		t.Errorf("got %q, want 99", got)
	}
}

func TestPackedAndZonedRoundTrip(t *testing.T) {
	inputs := []string{"0", "1", "-1", "123.45", "-99999999999.99", "0.01", "12.5", "+7"}
	for _, in := range inputs {
		for _, typ := range []uint16{typePacked, typeZoned} {
			f := field{sqlType: typ, precision: 13, scale: 2}
			if typ == typePacked {
				f.length = 13/2 + 1
			} else {
				f.length = 13
			}
			raw, err := encodeValue(f, in, time.UTC)
			if err != nil {
				t.Fatalf("encode %q as %s: %v", in, typeName(typ), err)
			}
			got, err := decodeValue(f, raw, time.UTC)
			if err != nil {
				t.Fatalf("decode %q as %s: %v", in, typeName(typ), err)
			}
			want := map[string]string{
				"0": "0.00", "1": "1.00", "-1": "-1.00", "123.45": "123.45",
				"-99999999999.99": "-99999999999.99", "0.01": "0.01", "12.5": "12.50", "+7": "7.00",
			}[in]
			if got != want {
				t.Errorf("%s round trip of %q = %q, want %q", typeName(typ), in, got, want)
			}
		}
	}
}

func TestEncodePackedBytes(t *testing.T) {
	f := field{sqlType: typePacked, precision: 5, scale: 2, length: 3}
	got, err := encodeValue(f, int64(-12), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x01, 0x20, 0x0D}; !bytes.Equal(got, want) {
		t.Errorf("got % x, want % x", got, want)
	}
}

func TestEncodeDecimalRejectsLoss(t *testing.T) {
	f := field{sqlType: typePacked, precision: 5, scale: 2, length: 3}
	for _, in := range []any{"1000.00", "1.234", "abc", "", "1.2.3", 1.005} {
		if _, err := encodeValue(f, in, time.UTC); err == nil {
			t.Errorf("encode %v: expected an error", in)
		}
	}
	// Trailing zeros beyond the scale are not a loss.
	if _, err := encodeValue(f, "1.2300", time.UTC); err != nil {
		t.Errorf("encode 1.2300: %v", err)
	}
}

func TestEncodeCharPadsWithEBCDICBlanks(t *testing.T) {
	f := field{sqlType: typeChar, length: 5, ccsid: 37}
	got, err := encodeValue(f, "AB", time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0xC1, 0xC2, 0x40, 0x40, 0x40}; !bytes.Equal(got, want) {
		t.Errorf("got % x, want % x", got, want)
	}
	if _, err := encodeValue(f, "TOOLONG", time.UTC); err == nil {
		t.Error("expected an error for a value longer than the column")
	}
}

func TestEncodeCharUTF16(t *testing.T) {
	f := field{sqlType: typeGraphic, length: 6, ccsid: 1200}
	got, err := encodeValue(f, "A", time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x00, 0x41, 0x00, 0x20, 0x00, 0x20}; !bytes.Equal(got, want) {
		t.Errorf("got % x, want % x", got, want)
	}
}

func TestVarcharRoundTrip(t *testing.T) {
	f := field{sqlType: typeVarchar | 1, length: 12, ccsid: 37}
	raw, err := encodeValue(f, "hello", time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if raw[0] != 0 || raw[1] != 5 || len(raw) != 12 {
		t.Fatalf("unexpected varchar encoding % x", raw)
	}
	got, err := decodeValue(f, raw, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if got != "hello" {
		t.Errorf("got %q, want hello", got)
	}
	if _, err := encodeValue(f, "this is far too long", time.UTC); err == nil {
		t.Error("expected an error for an over-long varchar")
	}
}

func TestDecodeCharKeepsTrailingBlanks(t *testing.T) {
	f := field{sqlType: typeChar, length: 4, ccsid: 37}
	got, err := decodeValue(f, []byte{0xC1, 0x40, 0x40, 0x40}, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if got != "A   " {
		t.Errorf("got %q, want %q", got, "A   ")
	}
}

func TestBinaryCharIsBytes(t *testing.T) {
	f := field{sqlType: typeChar, length: 3, ccsid: ccsidBinary}
	got, err := decodeValue(f, []byte{1, 2, 3}, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if b, ok := got.([]byte); !ok || !bytes.Equal(b, []byte{1, 2, 3}) {
		t.Errorf("got %#v", got)
	}
	raw, err := encodeValue(f, []byte{9}, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, []byte{9, 0, 0}) {
		t.Errorf("got % x, want 09 00 00", raw)
	}
}

func TestIntegers(t *testing.T) {
	for _, tc := range []struct {
		typ    uint16
		length int
		v      int64
	}{{typeSmallint, 2, -2}, {typeInteger, 4, 123456}, {typeBigint, 8, -9000000000}} {
		f := field{sqlType: tc.typ, length: tc.length}
		raw, err := encodeValue(f, tc.v, time.UTC)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decodeValue(f, raw, time.UTC)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.v {
			t.Errorf("%s: got %v, want %d", typeName(tc.typ), got, tc.v)
		}
	}
	if _, err := encodeValue(field{sqlType: typeSmallint, length: 2}, int64(40000), time.UTC); err == nil {
		t.Error("expected SMALLINT overflow error")
	}
	if _, err := encodeValue(field{sqlType: typeInteger, length: 4}, 1.5, time.UTC); err == nil {
		t.Error("expected error for a fractional INTEGER")
	}
}

func TestDateTimeValues(t *testing.T) {
	jkt := time.FixedZone("WIB", 7*3600)
	ts := time.Date(2026, 10, 13, 8, 1, 2, 123456000, jkt)

	dateField := field{sqlType: typeDate, length: 10, ccsid: 37}
	raw, err := encodeValue(dateField, ts, jkt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeValue(dateField, raw, jkt)
	if err != nil {
		t.Fatal(err)
	}
	if !got.(time.Time).Equal(time.Date(2026, 10, 13, 0, 0, 0, 0, jkt)) {
		t.Errorf("DATE round trip = %v", got)
	}

	tsField := field{sqlType: typeTimestamp, length: 26, ccsid: 37}
	raw, err = encodeValue(tsField, ts, jkt)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := decodeString(37, raw); s != "2026-10-13-08.01.02.123456" {
		t.Errorf("TIMESTAMP text = %q", s)
	}
	got, err = decodeValue(tsField, raw, jkt)
	if err != nil {
		t.Fatal(err)
	}
	if !got.(time.Time).Equal(ts) {
		t.Errorf("TIMESTAMP round trip = %v, want %v", got, ts)
	}

	timeField := field{sqlType: typeTime, length: 8, ccsid: 37}
	raw, err = encodeValue(timeField, "08:01:02", jkt)
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := decodeString(37, raw); s != "08.01.02" {
		t.Errorf("TIME text = %q", s)
	}
	got, err = decodeValue(timeField, raw, jkt)
	if err != nil {
		t.Fatal(err)
	}
	if got != "08:01:02" {
		t.Errorf("TIME decode = %v", got)
	}
}

func TestUnsupportedTypesError(t *testing.T) {
	for _, typ := range []uint16{typeDecfloat, typeBLOBLocator, typeCLOBLocator} {
		if _, err := decodeValue(field{sqlType: typ, length: 8}, make([]byte, 8), time.UTC); err == nil {
			t.Errorf("decode %s: expected an error", typeName(typ))
		}
		if _, err := encodeValue(field{sqlType: typ, length: 8}, "1", time.UTC); err == nil {
			t.Errorf("encode %s: expected an error", typeName(typ))
		}
	}
}

func TestUnregisteredCCSID(t *testing.T) {
	if _, err := encodeValue(field{sqlType: typeChar, length: 4, ccsid: 285}, "A", time.UTC); err == nil {
		t.Error("expected an error for an unregistered CCSID")
	}
}

func TestStatementType(t *testing.T) {
	tests := map[string]uint16{
		"select * from t":                      stmtTypeSelect,
		"  (SELECT 1 FROM SYSIBM.SYSDUMMY1)":   stmtTypeSelect,
		"WITH x AS (VALUES 1) SELECT * FROM x": stmtTypeSelect,
		"-- comment\nVALUES 1":                 stmtTypeSelect,
		"/* c */ insert into t values(?)":      stmtTypeOther,
		"CALL QSYS2.QCMDEXC('X')":              stmtTypeCall,
		"set schema x":                         stmtTypeUndetermined,
		"UPDATE QGPL.CMSBULK SET X = ?":        stmtTypeOther,
	}
	for q, want := range tests {
		if got := statementType(q); got != want {
			t.Errorf("statementType(%q) = %d, want %d", q, got, want)
		}
	}
}

func TestParseSuperExtendedFormat(t *testing.T) {
	// Two fields: CHAR(17) CCSID 37 named TRX_ID, DECIMAL(15,2) unnamed.
	name, _ := encodeString(37, "TRX_ID")
	nameEntry := make([]byte, 8+len(name))
	binary.BigEndian.PutUint32(nameEntry[0:4], uint32(len(nameEntry)))
	binary.BigEndian.PutUint16(nameEntry[4:6], 0x3840)
	binary.BigEndian.PutUint16(nameEntry[6:8], 37)
	copy(nameEntry[8:], name)

	d := make([]byte, formatHeaderLength+2*superFieldLength)
	binary.BigEndian.PutUint32(d[4:8], 2)
	binary.BigEndian.PutUint32(d[12:16], 17+8)
	f0 := d[formatHeaderLength:]
	binary.BigEndian.PutUint16(f0[2:4], typeChar)
	binary.BigEndian.PutUint32(f0[4:8], 17)
	binary.BigEndian.PutUint16(f0[12:14], 37)
	// Variable info for field 0 sits after both fixed descriptions.
	binary.BigEndian.PutUint32(f0[32:36], uint32(2*superFieldLength))
	binary.BigEndian.PutUint32(f0[36:40], uint32(len(nameEntry)))
	f1 := d[formatHeaderLength+superFieldLength:]
	binary.BigEndian.PutUint16(f1[2:4], typePacked|1)
	binary.BigEndian.PutUint32(f1[4:8], 8)
	binary.BigEndian.PutUint16(f1[8:10], 2)
	binary.BigEndian.PutUint16(f1[10:12], 15)
	d = append(d, nameEntry...)

	df, err := parseSuperExtendedFormat(d)
	if err != nil {
		t.Fatal(err)
	}
	want := []field{
		{sqlType: typeChar, length: 17, ccsid: 37, name: "TRX_ID"},
		{sqlType: typePacked | 1, length: 8, scale: 2, precision: 15},
	}
	if !reflect.DeepEqual(df.fields, want) || df.recordSize != 25 {
		t.Errorf("parsed %+v (record %d), want %+v", df.fields, df.recordSize, want)
	}
}
