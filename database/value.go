package database

import (
	"database/sql/driver"
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// SQL native type codes (SQLNativeType), nullable variants omitted: the
// server sets the low bit for a nullable column.
const (
	typeDate          = 384
	typeTime          = 388
	typeTimestamp     = 392
	typeDatalink      = 396
	typeBLOB          = 404
	typeCLOB          = 408
	typeDBCLOB        = 412
	typeVarchar       = 448
	typeChar          = 452
	typeLongVarchar   = 456
	typeVargraphic    = 464
	typeGraphic       = 468
	typeLongVargraph  = 472
	typeFloat         = 480
	typePacked        = 484
	typeZoned         = 488
	typeBigint        = 492
	typeInteger       = 496
	typeSmallint      = 500
	typeRowID         = 904
	typeVarbinary     = 908
	typeBinary        = 912
	typeBLOBLocator   = 960
	typeCLOBLocator   = 964
	typeDBCLOBLocator = 968
	typeDecfloat      = 996
)

// Date/time layouts for the ISO formats this client selects in
// SET_ATTRIBUTES (date format ISO, time format ISO), as the server renders
// them in character form.
const (
	layoutDate      = "2006-01-02"
	layoutTime      = "15.04.05"
	layoutTimestamp = "2006-01-02-15.04.05"
)

func typeName(t uint16) string {
	switch t {
	case typeDate:
		return "DATE"
	case typeTime:
		return "TIME"
	case typeTimestamp:
		return "TIMESTAMP"
	case typeDatalink:
		return "DATALINK"
	case typeBLOB:
		return "BLOB"
	case typeCLOB:
		return "CLOB"
	case typeDBCLOB:
		return "DBCLOB"
	case typeVarchar:
		return "VARCHAR"
	case typeChar:
		return "CHAR"
	case typeLongVarchar:
		return "LONG VARCHAR"
	case typeVargraphic:
		return "VARGRAPHIC"
	case typeGraphic:
		return "GRAPHIC"
	case typeLongVargraph:
		return "LONG VARGRAPHIC"
	case typeFloat:
		return "FLOAT"
	case typePacked:
		return "DECIMAL"
	case typeZoned:
		return "NUMERIC"
	case typeBigint:
		return "BIGINT"
	case typeInteger:
		return "INTEGER"
	case typeSmallint:
		return "SMALLINT"
	case typeRowID:
		return "ROWID"
	case typeVarbinary:
		return "VARBINARY"
	case typeBinary:
		return "BINARY"
	case typeBLOBLocator:
		return "BLOB LOCATOR"
	case typeCLOBLocator:
		return "CLOB LOCATOR"
	case typeDBCLOBLocator:
		return "DBCLOB LOCATOR"
	case typeDecfloat:
		return "DECFLOAT"
	default:
		return fmt.Sprintf("SQLTYPE(%d)", t)
	}
}

// charCCSID is the CCSID to use for a character-form field, substituting
// CCSID 37 for the 0 the server reports on some date/time fields.
func charCCSID(f field) int {
	if f.ccsid == 0 {
		return ccsidEBCDIC37
	}
	return f.ccsid
}

// decodeValue converts one field's raw bytes (exactly f.length of them)
// into a driver.Value. DECIMAL and NUMERIC come back as exact decimal
// strings (e.g. "-1234.50"), never float64. CHAR is returned with its
// trailing blanks, as JDBC's getString does. TIME comes back as an
// "hh:mm:ss" string; DATE and TIMESTAMP as time.Time in loc.
func decodeValue(f field, b []byte, loc *time.Location) (driver.Value, error) {
	switch f.baseType() {
	case typeChar:
		if f.ccsid == ccsidBinary {
			return append([]byte(nil), b...), nil
		}
		return decodeString(f.ccsid, b)

	case typeVarchar, typeLongVarchar, typeRowID, typeVarbinary, typeDatalink:
		data, err := varData(b, 1)
		if err != nil {
			return nil, err
		}
		if f.ccsid == ccsidBinary || f.baseType() == typeVarbinary || f.baseType() == typeRowID {
			return append([]byte(nil), data...), nil
		}
		return decodeString(f.ccsid, data)

	case typeGraphic:
		if f.ccsid == ccsidBinary {
			return append([]byte(nil), b...), nil
		}
		return decodeString(f.ccsid, b)

	case typeVargraphic, typeLongVargraph:
		data, err := varData(b, 2)
		if err != nil {
			return nil, err
		}
		if f.ccsid == ccsidBinary {
			return append([]byte(nil), data...), nil
		}
		return decodeString(f.ccsid, data)

	case typeBinary:
		return append([]byte(nil), b...), nil

	case typeBLOB, typeCLOB, typeDBCLOB:
		data, err := lobData(b, f.baseType() == typeDBCLOB)
		if err != nil {
			return nil, err
		}
		if f.baseType() == typeBLOB || f.ccsid == ccsidBinary {
			return append([]byte(nil), data...), nil
		}
		return decodeString(f.ccsid, data)

	case typeSmallint, typeInteger, typeBigint:
		if len(b) != f.length || (len(b) != 2 && len(b) != 4 && len(b) != 8) {
			return nil, fmt.Errorf("database: %s field has unexpected length %d", typeName(f.baseType()), len(b))
		}
		var v int64
		switch len(b) {
		case 2:
			v = int64(int16(binary.BigEndian.Uint16(b)))
		case 4:
			v = int64(int32(binary.BigEndian.Uint32(b)))
		case 8:
			v = int64(binary.BigEndian.Uint64(b))
		}
		if f.scale > 0 {
			return scaleDigits(strconv.FormatInt(v, 10), f.scale), nil
		}
		return v, nil

	case typeFloat:
		switch len(b) {
		case 4:
			return float64(math.Float32frombits(binary.BigEndian.Uint32(b))), nil
		case 8:
			return math.Float64frombits(binary.BigEndian.Uint64(b)), nil
		}
		return nil, fmt.Errorf("database: FLOAT field has unexpected length %d", len(b))

	case typePacked:
		return decodePacked(b, f.precision, f.scale)

	case typeZoned:
		return decodeZoned(b, f.precision, f.scale)

	case typeDate, typeTimestamp, typeTime:
		s, err := decodeString(charCCSID(f), b)
		if err != nil {
			return nil, err
		}
		s = strings.TrimRight(s, " \x00")
		switch f.baseType() {
		case typeDate:
			t, err := time.ParseInLocation(layoutDate, s, loc)
			if err != nil {
				return nil, fmt.Errorf("database: parse DATE %q: %w", s, err)
			}
			return t, nil
		case typeTimestamp:
			t, err := time.ParseInLocation(layoutTimestamp, s, loc)
			if err != nil {
				return nil, fmt.Errorf("database: parse TIMESTAMP %q: %w", s, err)
			}
			return t, nil
		default:
			return strings.ReplaceAll(s, ".", ":"), nil
		}
	}
	return nil, fmt.Errorf("database: column type %s is not supported by this client", typeName(f.baseType()))
}

// varData returns the data portion of a varying-length field: a 2-byte
// length prefix (in units of unitSize bytes) followed by the data.
func varData(b []byte, unitSize int) ([]byte, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("database: varying-length field shorter than its length prefix")
	}
	n := int(binary.BigEndian.Uint16(b[0:2])) * unitSize
	if 2+n > len(b) {
		return nil, fmt.Errorf("database: varying-length field declares %d bytes but has room for %d", n, len(b)-2)
	}
	return b[2 : 2+n], nil
}

// lobData returns the data portion of an inline LOB field: a 4-byte length
// prefix (characters for DBCLOB, bytes otherwise) followed by the data.
func lobData(b []byte, doubleByte bool) ([]byte, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("database: LOB field shorter than its length prefix")
	}
	n := int(binary.BigEndian.Uint32(b[0:4]))
	if doubleByte {
		n *= 2
	}
	if n < 0 || 4+n > len(b) {
		return nil, fmt.Errorf("database: LOB field declares %d bytes but has room for %d", n, len(b)-4)
	}
	return b[4 : 4+n], nil
}

// decodePacked decodes IBM packed decimal: two BCD digits per byte, the
// final low nibble holding the sign (0xB or 0xD negative, anything else
// positive), precision/2+1 bytes in all.
func decodePacked(b []byte, precision, scale int) (string, error) {
	if len(b) != precision/2+1 {
		return "", fmt.Errorf("database: DECIMAL(%d,%d) field has %d bytes, want %d", precision, scale, len(b), precision/2+1)
	}
	digits := make([]byte, 0, len(b)*2)
	for i, c := range b {
		hi, lo := c>>4, c&0x0F
		if hi > 9 {
			return "", fmt.Errorf("database: invalid packed decimal digit %#x", hi)
		}
		digits = append(digits, '0'+hi)
		if i < len(b)-1 {
			if lo > 9 {
				return "", fmt.Errorf("database: invalid packed decimal digit %#x", lo)
			}
			digits = append(digits, '0'+lo)
		}
	}
	negative := b[len(b)-1]&0x0F == 0x0B || b[len(b)-1]&0x0F == 0x0D
	return formatDecimal(string(digits), scale, negative), nil
}

// decodeZoned decodes IBM zoned decimal: one digit per byte in the low
// nibble, the final byte's zone (high nibble) holding the sign.
func decodeZoned(b []byte, precision, scale int) (string, error) {
	if len(b) != precision {
		return "", fmt.Errorf("database: NUMERIC(%d,%d) field has %d bytes, want %d", precision, scale, len(b), precision)
	}
	digits := make([]byte, len(b))
	for i, c := range b {
		d := c & 0x0F
		if d > 9 {
			return "", fmt.Errorf("database: invalid zoned decimal digit %#x", c)
		}
		digits[i] = '0' + d
	}
	zone := b[len(b)-1] >> 4
	negative := zone == 0x0B || zone == 0x0D
	return formatDecimal(string(digits), scale, negative), nil
}

// formatDecimal renders an unsigned digit string with an implied scale as
// a plain decimal string, without redundant leading zeros.
func formatDecimal(digits string, scale int, negative bool) string {
	s := scaleDigits(digits, scale)
	if negative && strings.Trim(s, "0.") != "" {
		s = "-" + s
	}
	return s
}

// scaleDigits inserts a decimal point scale digits from the right of a
// (possibly signed) integer digit string and strips leading zeros.
func scaleDigits(digits string, scale int) string {
	sign := ""
	if strings.HasPrefix(digits, "-") {
		sign, digits = "-", digits[1:]
	}
	for len(digits) <= scale {
		digits = "0" + digits
	}
	intPart := strings.TrimLeft(digits[:len(digits)-scale], "0")
	if intPart == "" {
		intPart = "0"
	}
	if scale == 0 {
		return sign + intPart
	}
	return sign + intPart + "." + digits[len(digits)-scale:]
}

// encodeValue converts a Go value into exactly f.length bytes in the field
// type the server described for a parameter marker. Values that cannot be
// represented without loss — strings too long for the column, numbers
// with more digits than the precision or fractional digits beyond the
// scale — are errors, never silently truncated or rounded. A nil value is
// handled by the caller (it becomes a NULL indicator).
func encodeValue(f field, v driver.Value, loc *time.Location) ([]byte, error) {
	out := make([]byte, f.length)
	switch f.baseType() {
	case typeChar, typeGraphic:
		if f.ccsid == ccsidBinary {
			b, err := bytesValue(v)
			if err != nil {
				return nil, err
			}
			if len(b) > f.length {
				return nil, fmt.Errorf("database: %d bytes do not fit %s(%d)", len(b), typeName(f.baseType()), f.length)
			}
			copy(out, b) // pad with 0x00, as AS400ByteArray does
			return out, nil
		}
		s, err := stringValue(v, loc, f)
		if err != nil {
			return nil, err
		}
		return padText(out, f, s)

	case typeVarchar, typeLongVarchar, typeVarbinary, typeVargraphic, typeLongVargraph:
		var data []byte
		if f.ccsid == ccsidBinary || f.baseType() == typeVarbinary {
			b, err := bytesValue(v)
			if err != nil {
				return nil, err
			}
			data = b
		} else {
			s, err := stringValue(v, loc, f)
			if err != nil {
				return nil, err
			}
			if data, err = encodeString(f.ccsid, s); err != nil {
				return nil, err
			}
		}
		if 2+len(data) > f.length {
			return nil, fmt.Errorf("database: %d bytes do not fit %s field of %d bytes", len(data), typeName(f.baseType()), f.length-2)
		}
		units := len(data)
		if f.baseType() == typeVargraphic || f.baseType() == typeLongVargraph {
			units /= 2
		}
		binary.BigEndian.PutUint16(out[0:2], uint16(units))
		copy(out[2:], data)
		return out, nil

	case typeBinary:
		b, err := bytesValue(v)
		if err != nil {
			return nil, err
		}
		if len(b) > f.length {
			return nil, fmt.Errorf("database: %d bytes do not fit BINARY(%d)", len(b), f.length)
		}
		copy(out, b)
		return out, nil

	case typeBLOB, typeCLOB, typeDBCLOB:
		var data []byte
		if f.baseType() == typeBLOB || f.ccsid == ccsidBinary {
			b, err := bytesValue(v)
			if err != nil {
				return nil, err
			}
			data = b
		} else {
			s, err := stringValue(v, loc, f)
			if err != nil {
				return nil, err
			}
			if data, err = encodeString(f.ccsid, s); err != nil {
				return nil, err
			}
		}
		if 4+len(data) > f.length {
			return nil, fmt.Errorf("database: %d bytes do not fit %s field of %d bytes", len(data), typeName(f.baseType()), f.length-4)
		}
		n := len(data)
		if f.baseType() == typeDBCLOB {
			n /= 2
		}
		binary.BigEndian.PutUint32(out[0:4], uint32(n))
		copy(out[4:], data)
		return out, nil

	case typeSmallint, typeInteger, typeBigint:
		if f.scale > 0 {
			return nil, fmt.Errorf("database: %s parameter with scale %d is not supported", typeName(f.baseType()), f.scale)
		}
		n, err := intValue(v)
		if err != nil {
			return nil, err
		}
		switch f.length {
		case 2:
			if n < math.MinInt16 || n > math.MaxInt16 {
				return nil, fmt.Errorf("database: %d out of range for SMALLINT", n)
			}
			binary.BigEndian.PutUint16(out, uint16(int16(n)))
		case 4:
			if n < math.MinInt32 || n > math.MaxInt32 {
				return nil, fmt.Errorf("database: %d out of range for INTEGER", n)
			}
			binary.BigEndian.PutUint32(out, uint32(int32(n)))
		case 8:
			binary.BigEndian.PutUint64(out, uint64(n))
		default:
			return nil, fmt.Errorf("database: %s field has unexpected length %d", typeName(f.baseType()), f.length)
		}
		return out, nil

	case typeFloat:
		x, err := floatValue(v)
		if err != nil {
			return nil, err
		}
		switch f.length {
		case 4:
			binary.BigEndian.PutUint32(out, math.Float32bits(float32(x)))
		case 8:
			binary.BigEndian.PutUint64(out, math.Float64bits(x))
		default:
			return nil, fmt.Errorf("database: FLOAT field has unexpected length %d", f.length)
		}
		return out, nil

	case typePacked, typeZoned:
		s, err := decimalValue(v)
		if err != nil {
			return nil, err
		}
		digits, negative, err := scaleToDigits(s, f.precision, f.scale)
		if err != nil {
			return nil, err
		}
		if f.baseType() == typePacked {
			return encodePacked(out, digits, negative)
		}
		return encodeZoned(out, digits, negative)

	case typeDate, typeTime, typeTimestamp:
		s, err := stringValue(v, loc, f)
		if err != nil {
			return nil, err
		}
		if f.baseType() == typeTime {
			s = strings.ReplaceAll(s, ":", ".")
		}
		return padText(out, field{sqlType: typeChar, length: f.length, ccsid: charCCSID(f)}, s)
	}
	return nil, fmt.Errorf("database: parameter type %s is not supported by this client", typeName(f.baseType()))
}

// padText encodes s in f's CCSID and blank-pads it to f.length.
func padText(out []byte, f field, s string) ([]byte, error) {
	data, err := encodeString(f.ccsid, s)
	if err != nil {
		return nil, err
	}
	if len(data) > f.length {
		return nil, fmt.Errorf("database: value %q (%d bytes) does not fit %s field of %d bytes", s, len(data), typeName(f.baseType()), f.length)
	}
	pad, err := blank(f.ccsid)
	if err != nil {
		return nil, err
	}
	n := copy(out, data)
	for ; n+len(pad) <= len(out); n += len(pad) {
		copy(out[n:], pad)
	}
	return out, nil
}

func bytesValue(v driver.Value) ([]byte, error) {
	switch x := v.(type) {
	case []byte:
		return x, nil
	case string:
		return []byte(x), nil
	}
	return nil, fmt.Errorf("database: cannot use %T as binary data", v)
}

// stringValue renders v as character data, formatting time.Time in the
// ISO layout matching f's type (TIMESTAMP precision follows f.length).
func stringValue(v driver.Value, loc *time.Location, f field) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case []byte:
		return string(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	case bool:
		if x {
			return "1", nil
		}
		return "0", nil
	case time.Time:
		x = x.In(loc)
		switch f.baseType() {
		case typeDate:
			return x.Format(layoutDate), nil
		case typeTime:
			return x.Format(layoutTime), nil
		default:
			s := x.Format(layoutTimestamp)
			if frac := f.length - len(s) - 1; f.baseType() == typeTimestamp && frac > 0 {
				s += x.Format("." + strings.Repeat("0", frac))
			} else if f.baseType() != typeTimestamp {
				s += x.Format(".000000")
			}
			return s, nil
		}
	}
	return "", fmt.Errorf("database: cannot use %T as character data", v)
}

func intValue(v driver.Value) (int64, error) {
	switch x := v.(type) {
	case int64:
		return x, nil
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	case float64:
		if x != math.Trunc(x) || x < math.MinInt64 || x >= math.MaxInt64 {
			return 0, fmt.Errorf("database: %v is not an integer", x)
		}
		return int64(x), nil
	case string:
		return strconv.ParseInt(strings.TrimSpace(x), 10, 64)
	case []byte:
		return strconv.ParseInt(strings.TrimSpace(string(x)), 10, 64)
	}
	return 0, fmt.Errorf("database: cannot use %T as an integer", v)
}

func floatValue(v driver.Value) (float64, error) {
	switch x := v.(type) {
	case float64:
		return x, nil
	case int64:
		return float64(x), nil
	case string:
		return strconv.ParseFloat(strings.TrimSpace(x), 64)
	case []byte:
		return strconv.ParseFloat(strings.TrimSpace(string(x)), 64)
	}
	return 0, fmt.Errorf("database: cannot use %T as a float", v)
}

func decimalValue(v driver.Value) (string, error) {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x), nil
	case []byte:
		return strings.TrimSpace(string(x)), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return "", fmt.Errorf("database: %v cannot be stored as a decimal", x)
		}
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	case bool:
		if x {
			return "1", nil
		}
		return "0", nil
	}
	return "", fmt.Errorf("database: cannot use %T as a decimal", v)
}

// scaleToDigits converts a plain decimal string ("-12.5", "300", ".25")
// into exactly precision digits with an implied scale, rejecting input
// that would lose integer digits or non-zero fractional digits.
func scaleToDigits(s string, precision, scale int) (digits string, negative bool, err error) {
	orig := s
	switch {
	case strings.HasPrefix(s, "-"):
		negative, s = true, s[1:]
	case strings.HasPrefix(s, "+"):
		s = s[1:]
	}
	intPart, fracPart, _ := strings.Cut(s, ".")
	if intPart == "" && fracPart == "" {
		return "", false, fmt.Errorf("database: %q is not a decimal number", orig)
	}
	for _, part := range []string{intPart, fracPart} {
		for _, c := range part {
			if c < '0' || c > '9' {
				return "", false, fmt.Errorf("database: %q is not a decimal number", orig)
			}
		}
	}
	if len(fracPart) > scale {
		if strings.Trim(fracPart[scale:], "0") != "" {
			return "", false, fmt.Errorf("database: %q has more than %d fractional digits", orig, scale)
		}
		fracPart = fracPart[:scale]
	}
	fracPart += strings.Repeat("0", scale-len(fracPart))
	intPart = strings.TrimLeft(intPart, "0")
	if len(intPart) > precision-scale {
		return "", false, fmt.Errorf("database: %q does not fit DECIMAL(%d,%d)", orig, precision, scale)
	}
	digits = strings.Repeat("0", precision-scale-len(intPart)) + intPart + fracPart
	if strings.Trim(digits, "0") == "" {
		negative = false
	}
	return digits, negative, nil
}

// encodePacked writes digits (precision of them) as packed decimal into
// out (precision/2+1 bytes), using sign nibble 0xF (positive) or 0xD, as
// JTOpen's AS400PackedDecimal does.
func encodePacked(out []byte, digits string, negative bool) ([]byte, error) {
	if len(out) != len(digits)/2+1 {
		return nil, fmt.Errorf("database: packed field of %d bytes cannot hold %d digits", len(out), len(digits))
	}
	// Left-pad to an odd digit count so the digits plus sign fill whole bytes.
	if len(digits)%2 == 0 {
		digits = "0" + digits
	}
	nibbles := make([]byte, 0, len(digits)+1)
	for i := 0; i < len(digits); i++ {
		nibbles = append(nibbles, digits[i]-'0')
	}
	if negative {
		nibbles = append(nibbles, 0x0D)
	} else {
		nibbles = append(nibbles, 0x0F)
	}
	for i := range out {
		out[i] = nibbles[2*i]<<4 | nibbles[2*i+1]
	}
	return out, nil
}

// encodeZoned writes digits as zoned decimal: zone 0xF on every digit but
// the last, whose zone carries the sign (0xF positive, 0xD negative).
func encodeZoned(out []byte, digits string, negative bool) ([]byte, error) {
	if len(out) != len(digits) {
		return nil, fmt.Errorf("database: zoned field of %d bytes cannot hold %d digits", len(out), len(digits))
	}
	for i := 0; i < len(digits); i++ {
		out[i] = 0xF0 | (digits[i] - '0')
	}
	if negative {
		out[len(out)-1] = 0xD0 | (out[len(out)-1] & 0x0F)
	}
	return out, nil
}
