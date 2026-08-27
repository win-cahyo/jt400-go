package as400

import (
	"encoding/binary"
	"fmt"
	"io"
)

// HeaderLength is the size in bytes of the common host-server datastream
// header shared by as-signon, as-dtaq, as-rmtcmd (and every other "Client
// Access" host server except as-ddm/Record Level Access, which uses a
// separate DDM framing not implemented by this library).
const HeaderLength = 20

// Request is a single outbound host-server datastream: the common 20-byte
// header followed by a body that is service-defined — typically a fixed
// "template" region followed by zero or more LL/CP encoded parameters (see
// EncodeParams). Correlation is overwritten by Connection.Call.
type Request struct {
	ServerID ServerID
	// HeaderID is usually 0. A handful of connection-handshake datastreams
	// (exchange-random-seed, start-server, signon-exchange-attributes)
	// instead pack a one-byte "client attributes" value into its high byte;
	// use AttrHeaderID to build that value.
	HeaderID    uint16
	Correlation uint32
	TemplateLen uint16
	ReqRepID    uint16
	Body        []byte
}

// AttrHeaderID packs a client-attributes byte into the header ID field, as
// used by the connection-handshake datastreams. The low byte (server
// attributes) is only meaningful on replies; pass 0 when building a request.
func AttrHeaderID(clientAttr byte) uint16 {
	return uint16(clientAttr) << 8
}

// Encode serializes the request to its wire form.
func (r Request) Encode() []byte {
	buf := make([]byte, HeaderLength+len(r.Body))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(buf)))
	binary.BigEndian.PutUint16(buf[4:6], r.HeaderID)
	binary.BigEndian.PutUint16(buf[6:8], uint16(r.ServerID))
	// Bytes 8-11 (CS instance) are always 0 for the services this library targets.
	binary.BigEndian.PutUint32(buf[12:16], r.Correlation)
	binary.BigEndian.PutUint16(buf[16:18], r.TemplateLen)
	binary.BigEndian.PutUint16(buf[18:20], r.ReqRepID)
	copy(buf[HeaderLength:], r.Body)
	return buf
}

// Reply is a single inbound host-server datastream, decoded from its wire
// form by ReadReply.
type Reply struct {
	HeaderID    uint16
	ServerID    ServerID
	Correlation uint32
	TemplateLen uint16
	// ReqRepID is the reply's own opcode (JTOpen refers to this value as
	// the reply class's hashCode).
	ReqRepID uint16
	// Body is everything after the 20-byte header.
	Body []byte
}

// ClientAttr and ServerAttr split HeaderID back into the two attribute
// bytes used by the connection-handshake reply datastreams.
func (r *Reply) ClientAttr() byte { return byte(r.HeaderID >> 8) }
func (r *Reply) ServerAttr() byte { return byte(r.HeaderID) }

// RC returns the 4-byte return code conventionally stored as the first
// field of a reply's body (datastream offset 20). This convention holds for
// every reply type this library decodes, but is not a guaranteed property
// of the header itself — callers should confirm applicability against the
// specific reply's documented layout when adding new opcodes.
func (r *Reply) RC() (uint32, bool) {
	if len(r.Body) < 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(r.Body[0:4]), true
}

// ReadReply reads one complete datastream from r: the 20-byte header, then
// exactly (declared length - 20) more bytes. The server ID's high byte is
// validated to be 0xE0, matching every known IBM i "Client Access" host
// server ID.
func ReadReply(r io.Reader) (*Reply, error) {
	hdr := make([]byte, HeaderLength)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("as400: read header: %w", err)
	}
	if hdr[6] != 0xE0 {
		return nil, fmt.Errorf("as400: unexpected server id byte %#x (want 0xE0xx)", hdr[6])
	}
	length := binary.BigEndian.Uint32(hdr[0:4])
	if length < HeaderLength {
		return nil, fmt.Errorf("as400: reply declares length %d, shorter than the header itself", length)
	}
	body := make([]byte, length-HeaderLength)
	if len(body) > 0 {
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, fmt.Errorf("as400: read body: %w", err)
		}
	}
	return &Reply{
		HeaderID:    binary.BigEndian.Uint16(hdr[4:6]),
		ServerID:    ServerID(binary.BigEndian.Uint16(hdr[6:8])),
		Correlation: binary.BigEndian.Uint32(hdr[12:16]),
		TemplateLen: binary.BigEndian.Uint16(hdr[16:18]),
		ReqRepID:    binary.BigEndian.Uint16(hdr[18:20]),
		Body:        body,
	}, nil
}
