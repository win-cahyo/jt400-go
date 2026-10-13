package database

import (
	"encoding/binary"
	"fmt"
)

// Extended data format layout (DBExtendedDataFormat): a 16-byte header —
// consistency token, field count, reserved, record size — then one 64-byte
// description per field.
const (
	formatHeaderLength = 16
	formatFieldLength  = 64
)

// field describes one result column or parameter marker, as the server
// reports it in an extended data format.
type field struct {
	sqlType   uint16 // SQLNativeType value; the low bit set means nullable
	length    int    // bytes the field occupies in a row, including any length prefix
	scale     int
	precision int
	ccsid     int
	name      string
}

func (f field) baseType() uint16 { return f.sqlType &^ 1 }
func (f field) nullable() bool   { return f.sqlType&1 != 0 }

type dataFormat struct {
	fields     []field
	recordSize int
}

func parseDataFormat(d []byte) (*dataFormat, error) {
	if len(d) < formatHeaderLength {
		return nil, fmt.Errorf("database: data format too short (%d bytes)", len(d))
	}
	n := int(binary.BigEndian.Uint32(d[4:8]))
	if n < 0 || formatHeaderLength+n*formatFieldLength > len(d) {
		return nil, fmt.Errorf("database: data format declares %d fields but holds %d bytes", n, len(d))
	}
	df := &dataFormat{
		fields:     make([]field, n),
		recordSize: int(binary.BigEndian.Uint32(d[12:16])),
	}
	for i := range df.fields {
		b := d[formatHeaderLength+i*formatFieldLength:]
		f := field{
			sqlType:   binary.BigEndian.Uint16(b[2:4]),
			length:    int(binary.BigEndian.Uint32(b[4:8])),
			scale:     int(binary.BigEndian.Uint16(b[8:10])),
			precision: int(binary.BigEndian.Uint16(b[10:12])),
			ccsid:     int(binary.BigEndian.Uint16(b[12:14])),
		}
		nameLen := int(binary.BigEndian.Uint16(b[30:32]))
		nameCCSID := int(binary.BigEndian.Uint16(b[32:34]))
		if nameLen > 0 && 34+nameLen <= formatFieldLength {
			f.name = decodeServerText(nameCCSID, b[34:34+nameLen])
		}
		df.fields[i] = f
	}
	return df, nil
}

// superFieldLength is the fixed part of each field description in a
// super-extended data format (DBSuperExtendedDataFormat), which the server
// may use in place of the extended one. Its first 32 bytes match the
// extended layout; names move to a variable-length area after the fixed
// descriptions.
const superFieldLength = 48

// parseSuperExtendedFormat reads a DBSuperExtendedDataFormat: the same
// header and fixed field attributes as the extended format, with each
// field's name in an LL/CP entry (code point 0x3840: CCSID, then the name)
// located by an offset, relative to that field's description, at +32,
// within variable information whose total length is at +36.
func parseSuperExtendedFormat(d []byte) (*dataFormat, error) {
	if len(d) < formatHeaderLength {
		return nil, fmt.Errorf("database: data format too short (%d bytes)", len(d))
	}
	n := int(binary.BigEndian.Uint32(d[4:8]))
	if n < 0 || formatHeaderLength+n*superFieldLength > len(d) {
		return nil, fmt.Errorf("database: data format declares %d fields but holds %d bytes", n, len(d))
	}
	df := &dataFormat{
		fields:     make([]field, n),
		recordSize: int(binary.BigEndian.Uint32(d[12:16])),
	}
	for i := range df.fields {
		base := formatHeaderLength + i*superFieldLength
		b := d[base : base+superFieldLength]
		f := field{
			sqlType:   binary.BigEndian.Uint16(b[2:4]),
			length:    int(binary.BigEndian.Uint32(b[4:8])),
			scale:     int(binary.BigEndian.Uint16(b[8:10])),
			precision: int(binary.BigEndian.Uint16(b[10:12])),
			ccsid:     int(binary.BigEndian.Uint16(b[12:14])),
		}
		varOffset := int(binary.BigEndian.Uint32(b[32:36]))
		varLength := int(binary.BigEndian.Uint32(b[36:40]))
		for pos := 0; pos+8 <= varLength; {
			entry := base + varOffset + pos
			if entry < 0 || entry+8 > len(d) {
				break
			}
			ll := int(binary.BigEndian.Uint32(d[entry : entry+4]))
			if ll < 8 || entry+ll > len(d) {
				break
			}
			if binary.BigEndian.Uint16(d[entry+4:entry+6]) == 0x3840 {
				nameCCSID := int(binary.BigEndian.Uint16(d[entry+6 : entry+8]))
				f.name = decodeServerText(nameCCSID, d[entry+8:entry+ll])
				break
			}
			pos += ll
		}
		df.fields[i] = f
	}
	return df, nil
}

// encodeParameterFormat builds the extended data format sent with
// CHANGE_DESCRIPTOR to describe the parameter-marker data that follows on
// each execute, mirroring AS400JDBCPreparedStatementImpl.changeDescriptor:
// consistency token 1, each field marked nullable and left unnamed.
func encodeParameterFormat(fields []field) []byte {
	b := make([]byte, formatHeaderLength+len(fields)*formatFieldLength)
	binary.BigEndian.PutUint32(b[0:4], 1)
	binary.BigEndian.PutUint32(b[4:8], uint32(len(fields)))
	binary.BigEndian.PutUint32(b[12:16], uint32(recordSize(fields)))
	for i, f := range fields {
		fb := b[formatHeaderLength+i*formatFieldLength:]
		binary.BigEndian.PutUint16(fb[0:2], formatFieldLength)
		binary.BigEndian.PutUint16(fb[2:4], f.sqlType|1)
		binary.BigEndian.PutUint32(fb[4:8], uint32(f.length))
		binary.BigEndian.PutUint16(fb[8:10], uint16(f.scale))
		binary.BigEndian.PutUint16(fb[10:12], uint16(f.precision))
		binary.BigEndian.PutUint16(fb[12:14], uint16(f.ccsid))
	}
	return b
}

func recordSize(fields []field) int {
	n := 0
	for _, f := range fields {
		n += f.length
	}
	return n
}

// Extended data layout (DBExtendedData): a 20-byte header — consistency
// token, row count, column count, indicator size, reserved, row size —
// then rowCount*columnCount null indicators, then rowCount fixed-size rows.
const dataHeaderLength = 20

type resultData struct {
	raw           []byte
	rowCount      int
	columnCount   int
	indicatorSize int
	rowSize       int
}

func parseResultData(d []byte) (*resultData, error) {
	if len(d) < dataHeaderLength {
		return nil, fmt.Errorf("database: result data too short (%d bytes)", len(d))
	}
	rd := &resultData{
		raw:           d,
		rowCount:      int(binary.BigEndian.Uint32(d[4:8])),
		columnCount:   int(binary.BigEndian.Uint16(d[8:10])),
		indicatorSize: int(binary.BigEndian.Uint16(d[10:12])),
		rowSize:       int(binary.BigEndian.Uint32(d[16:20])),
	}
	need := dataHeaderLength + rd.rowCount*(rd.columnCount*rd.indicatorSize+rd.rowSize)
	if rd.rowCount < 0 || need > len(d) {
		return nil, fmt.Errorf("database: result data declares %d rows of %d bytes but holds %d bytes", rd.rowCount, rd.rowSize, len(d))
	}
	return rd, nil
}

// indicator returns the null indicator for (row, col); 0 when the server
// sent no indicators.
func (rd *resultData) indicator(row, col int) int16 {
	if rd.indicatorSize == 0 {
		return 0
	}
	off := dataHeaderLength + rd.indicatorSize*(row*rd.columnCount+col)
	return int16(binary.BigEndian.Uint16(rd.raw[off : off+2]))
}

func (rd *resultData) row(i int) []byte {
	start := dataHeaderLength + rd.rowCount*rd.columnCount*rd.indicatorSize + i*rd.rowSize
	return rd.raw[start : start+rd.rowSize]
}

// encodeParameterData builds one row of parameter-marker data in the
// extended data layout (2-byte indicators), as
// AS400JDBCPreparedStatementImpl.commonExecuteBefore does for a
// non-batched execute. values[i] is the already-encoded field (exactly
// fields[i].length bytes) or nil for SQL NULL.
func encodeParameterData(fields []field, values [][]byte) []byte {
	const indicatorSize = 2
	rowSize := recordSize(fields)
	b := make([]byte, dataHeaderLength+len(fields)*indicatorSize+rowSize)
	binary.BigEndian.PutUint32(b[0:4], 1)
	binary.BigEndian.PutUint32(b[4:8], 1)
	binary.BigEndian.PutUint16(b[8:10], uint16(len(fields)))
	binary.BigEndian.PutUint16(b[10:12], indicatorSize)
	binary.BigEndian.PutUint32(b[16:20], uint32(rowSize))

	row := b[dataHeaderLength+len(fields)*indicatorSize:]
	off := 0
	for i, f := range fields {
		ind := b[dataHeaderLength+i*indicatorSize:]
		if values[i] == nil {
			binary.BigEndian.PutUint16(ind[0:2], 0xFFFF) // INDICATOR_NULL (-1); data left zeroed
		} else {
			copy(row[off:off+f.length], values[i])
		}
		off += f.length
	}
	return b
}
