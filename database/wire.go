package database

import (
	"encoding/binary"
	"fmt"

	"github.com/win-cahyo/jt400-go/as400"
	"github.com/win-cahyo/jt400-go/as400/auth"
)

// Function IDs (the datastream ReqRepID) used by this package, from
// DBSQLAttributesDS, DBSQLRPBDS, DBSQLDescriptorDS and DBSQLRequestDS.
const (
	fnSetAttributes      = 0x1F80
	fnRetrieveAttributes = 0x1F81
	fnCreateRPB          = 0x1D00
	fnDeleteRPB          = 0x1D02
	fnChangeDescriptor   = 0x1E00
	fnDeleteDescriptor   = 0x1E01
	fnPrepareDescribe    = 0x1803
	fnExecute            = 0x1805
	fnCommit             = 0x1807
	fnRollback           = 0x1808
	fnClose              = 0x180A
	fnFetch              = 0x180B
	fnOpenDescribeFetch  = 0x180E
)

// Operation-result bitmap bits (DBBaseRequestDS.ORS_BITMAP_*): what the
// server should send back. A request with a zero bitmap gets no reply at
// all, and must be sent with as400.Connection.Send rather than Call.
const (
	orsReturnData            = 0x80000000
	orsMessageID             = 0x40000000
	orsFirstLevelText        = 0x20000000
	orsDataFormat            = 0x08000000
	orsResultData            = 0x04000000
	orsSQLCA                 = 0x02000000
	orsServerAttributes      = 0x01000000
	orsParameterMarkerFormat = 0x00800000

	// orsReply is the bitmap every reply-producing request in this package
	// starts from: return data, plus the message ID and first-level text so
	// that a failure carries its own explanation (JTOpen instead fetches it
	// with a follow-up request in JDError.getReason).
	orsReply = orsReturnData | orsMessageID | orsFirstLevelText
)

// Reply code points (DBBaseReplyDS.parse).
const (
	cpMessageID          = 0x3801
	cpFirstLevelText     = 0x3802
	cpServerAttributes   = 0x3804
	cpOriginalFormat     = 0x3805
	cpOriginalData       = 0x3806
	cpSQLCA              = 0x3807
	cpOriginalParmFormat = 0x3808
	cpExtendedFormat     = 0x380C
	cpExtendedParmFormat = 0x380D
	cpExtendedData       = 0x380E
	cpSuperExtFormat     = 0x3812
	cpSuperExtParmFormat = 0x3813
	cpVariableData       = 0x3901
)

// Error classes (DBBaseReplyDS.getErrorClass) with special meaning here.
const (
	errorClassSQL        = 1 // returnCode is the SQLCODE
	errorClassHostServer = 2 // returnCode 700/701 marks end of data on a fetch
)

// templateLength is the fixed template every as-database request and reply
// carries between the 20-byte header and its LL/CP parameters.
const templateLength = 20

// request is one as-database request datastream, mirroring
// DBBaseRequestDS.initialize: the template holds the operation-result
// bitmap, the RPB (statement) handle in its three handle slots, and the
// parameter-marker descriptor handle.
type request struct {
	functionID uint16
	rpbID      uint16
	ors        uint32
	pmHandle   uint16
	params     []as400.Param
}

func (r *request) add(cp uint16, data []byte) {
	r.params = append(r.params, as400.Param{CodePoint: cp, Data: data})
}

func (r *request) addByte(cp uint16, v byte) { r.add(cp, []byte{v}) }

func (r *request) addShort(cp uint16, v uint16) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	r.add(cp, b)
}

func (r *request) addInt(cp uint16, v uint32) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	r.add(cp, b)
}

// addText adds a CCSID-tagged string with a 2-byte length:
// DBBaseRequestDS.addParameter(int, ConvTable, String).
func (r *request) addText(cp uint16, ccsid int, data []byte) {
	b := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(b[0:2], uint16(ccsid))
	binary.BigEndian.PutUint16(b[2:4], uint16(len(data)))
	copy(b[4:], data)
	r.add(cp, b)
}

// addLongText adds a CCSID-tagged string with a 4-byte length, the
// "extended statement text" form used on V5R4 and later:
// DBBaseRequestDS.addParameter(int, boolean, ConvTable, String).
func (r *request) addLongText(cp uint16, ccsid int, data []byte) {
	b := make([]byte, 6+len(data))
	binary.BigEndian.PutUint16(b[0:2], uint16(ccsid))
	binary.BigEndian.PutUint32(b[2:6], uint32(len(data)))
	copy(b[6:], data)
	r.add(cp, b)
}

// addName adds an SQL object name (statement or cursor name) — always
// letters and digits here, so encoded with this library's restricted
// CCSID 37 table and tagged 37 regardless of the server job's CCSID.
func (r *request) addName(cp uint16, name string) error {
	enc, err := auth.EncodeEBCDIC(name)
	if err != nil {
		return fmt.Errorf("database: name %q: %w", name, err)
	}
	r.addText(cp, ccsidEBCDIC37, enc)
	return nil
}

func (r *request) encode() as400.Request {
	body := make([]byte, templateLength, templateLength+64)
	binary.BigEndian.PutUint32(body[0:4], r.ors)
	// body[4:8] reserved.
	binary.BigEndian.PutUint16(body[8:10], r.rpbID)  // return ORS handle
	binary.BigEndian.PutUint16(body[10:12], r.rpbID) // fill ORS handle
	// body[12:14] based-on ORS handle: always 0 (no request chaining).
	binary.BigEndian.PutUint16(body[14:16], r.rpbID) // RPB handle
	binary.BigEndian.PutUint16(body[16:18], r.pmHandle)
	binary.BigEndian.PutUint16(body[18:20], uint16(len(r.params)))
	body = append(body, as400.EncodeParams(r.params...)...)
	return as400.Request{
		ServerID:    as400.ServerDatabase,
		TemplateLen: templateLength,
		ReqRepID:    r.functionID,
		Body:        body,
	}
}

// reply is a decoded as-database reply (DBBaseReplyDS), keeping only the
// pieces this package uses.
type reply struct {
	errorClass uint16
	returnCode int32

	messageID string
	message   string

	serverAttributes []byte
	sqlca            []byte
	dataFormat       *dataFormat
	paramFormat      *dataFormat
	resultData       *resultData
}

func parseReply(r *as400.Reply) (*reply, error) {
	body := r.Body
	if len(body) < templateLength {
		return nil, fmt.Errorf("database: reply %#04x too short (%d bytes)", r.ReqRepID, len(body))
	}
	if body[4]&0x80 != 0 {
		// DBBaseReplyDS: bit 0 of offset 24 flags compressed data. This
		// package never requests compression, so a compressed reply means
		// the exchange is not what we think it is.
		return nil, fmt.Errorf("database: reply %#04x is compressed, which this client never requests", r.ReqRepID)
	}
	vlfCompressed := binary.BigEndian.Uint16(body[0:2])&0x0001 != 0

	rep := &reply{
		errorClass: binary.BigEndian.Uint16(body[14:16]),
		returnCode: int32(binary.BigEndian.Uint32(body[16:20])),
	}
	params, err := as400.DecodeParams(body[templateLength:])
	if err != nil {
		return nil, fmt.Errorf("database: decode reply %#04x: %w", r.ReqRepID, err)
	}
	for _, p := range params {
		d := p.Data
		switch p.CodePoint {
		case cpMessageID:
			if len(d) > 2 {
				rep.messageID = decodeServerText(int(binary.BigEndian.Uint16(d[0:2])), d[2:])
			}
		case cpFirstLevelText:
			if len(d) > 4 {
				rep.message = decodeServerText(int(binary.BigEndian.Uint16(d[0:2])), d[4:])
			}
		case cpServerAttributes:
			if len(d) > 2 {
				rep.serverAttributes = d[2:]
			}
		case cpSQLCA:
			rep.sqlca = d
		case cpExtendedFormat:
			if len(d) > 0 {
				if rep.dataFormat, err = parseDataFormat(d); err != nil {
					return nil, err
				}
			}
		case cpExtendedParmFormat:
			if len(d) > 0 {
				if rep.paramFormat, err = parseDataFormat(d); err != nil {
					return nil, err
				}
			}
		case cpSuperExtFormat:
			if len(d) > 0 {
				if rep.dataFormat, err = parseSuperExtendedFormat(d); err != nil {
					return nil, err
				}
			}
		case cpSuperExtParmFormat:
			if len(d) > 0 {
				if rep.paramFormat, err = parseSuperExtendedFormat(d); err != nil {
					return nil, err
				}
			}
		case cpExtendedData:
			if len(d) > 0 {
				if vlfCompressed {
					return nil, fmt.Errorf("database: result data uses variable-length field compression, which this client never requests")
				}
				if rep.resultData, err = parseResultData(d); err != nil {
					return nil, err
				}
			}
		case cpOriginalFormat, cpOriginalParmFormat, cpOriginalData, cpVariableData:
			if len(d) > 0 {
				return nil, fmt.Errorf("database: reply uses data format code point %#04x; this client only supports the extended and super-extended formats", p.CodePoint)
			}
		}
	}
	return rep, nil
}

// failed reports whether the reply carries an error (as opposed to success
// or a warning): JTOpen throws only when errorClass != 0 and the return
// code is negative, and posts a warning otherwise.
func (r *reply) failed() bool {
	return r.errorClass != 0 && r.returnCode < 0
}

// endOfData reports whether a fetch-type reply signals that the cursor has
// no more rows (JDServerRowCache.fetch): SQLCODE +100, or host-server
// return code 700/701.
func (r *reply) endOfData() bool {
	return (r.errorClass == errorClassSQL && r.returnCode == 100) ||
		(r.errorClass == errorClassHostServer && (r.returnCode == 700 || r.returnCode == 701))
}

// cursorClosedByServer reports host-server return code 700: the server
// has already closed the cursor itself, so the client must not close it.
func (r *reply) cursorClosedByServer() bool {
	return r.errorClass == errorClassHostServer && r.returnCode == 700
}

// sqlcaSQLState and sqlcaRowCount read SQLCA fields at DBReplySQLCA's
// offsets (SQLSTATE at 131, SQLERRD(3) at 104). An SQLCA of 6 bytes or
// less (just the LL/CP header in JTOpen's terms) is empty.
func (r *reply) sqlState() string {
	if len(r.sqlca) < 136 {
		return ""
	}
	return decodeServerText(ccsidEBCDIC37, r.sqlca[131:136])
}

func (r *reply) rowCount() int64 {
	if len(r.sqlca) < 108 {
		return 0
	}
	return int64(int32(binary.BigEndian.Uint32(r.sqlca[104:108])))
}
