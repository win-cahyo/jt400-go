package rmtcmd

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/win-cahyo/jt400-go/as400"
	"github.com/win-cahyo/jt400-go/as400/auth"
)

// MessageOption selects how many messages the server should attach to a
// RunCommand/CallProgram reply.
type MessageOption byte

const (
	MessageOptionUpTo10 MessageOption = 0
	MessageOptionNone   MessageOption = 1
	MessageOptionAll    MessageOption = 2
)

// remapMessageCount reproduces RCRunCommandRequestDataStream/
// RCCallProgramRequestDataStream's dataStreamLevel-dependent remapping of
// the client-facing MessageOption values onto the wire byte the server
// actually expects.
func remapMessageCount(dsLevel uint16, opt MessageOption) byte {
	count := opt
	if dsLevel < 7 && count == MessageOptionAll {
		count = MessageOptionUpTo10
	}
	switch {
	case dsLevel >= 11:
		if count == MessageOptionUpTo10 {
			return 5
		}
		if count == MessageOptionAll {
			return 6
		}
	case dsLevel >= 10:
		if count == MessageOptionUpTo10 {
			return 3
		}
		if count == MessageOptionAll {
			return 4
		}
	}
	return byte(count)
}

// buildExchangeAttributesRequest builds the rmtcmd-specific exchange-
// attributes request (opcode 0x1001), sent once per connection before any
// RunCommand/CallProgram request. The client CCSID is fixed at 37 (EBCDIC
// US English, matching this library's restricted EBCDIC assumptions
// elsewhere) and the NLV at "2924" (English) — JTOpen's own comment notes
// the server doesn't currently act on either the NLV or the echoed client
// CCSID for anything beyond message-language selection.
func buildExchangeAttributesRequest() as400.Request {
	body := make([]byte, 14)
	binary.BigEndian.PutUint32(body[0:4], 37)
	copy(body[4:8], []byte{0xF2, 0xF9, 0xF2, 0xF4}) // "2924", zoned EBCDIC digits
	binary.BigEndian.PutUint32(body[8:12], 1)       // client version
	return as400.Request{ServerID: as400.ServerRemoteCommand, ReqRepID: 0x1001, TemplateLen: 14, Body: body}
}

func parseExchangeAttributesReply(reply *as400.Reply) (ccsid uint32, dsLevel uint16, err error) {
	if len(reply.Body) < 2 {
		return 0, 0, fmt.Errorf("rmtcmd: exchange-attributes reply too short")
	}
	rc := binary.BigEndian.Uint16(reply.Body[0:2])
	if rc != 0 {
		return 0, 0, fmt.Errorf("rmtcmd: exchange attributes failed, rc=%#04x", rc)
	}
	if len(reply.Body) < 16 {
		return 0, 0, fmt.Errorf("rmtcmd: exchange-attributes reply missing fixed fields")
	}
	ccsid = binary.BigEndian.Uint32(reply.Body[2:6])
	dsLevel = binary.BigEndian.Uint16(reply.Body[14:16])
	return ccsid, dsLevel, nil
}

// buildRunCommandRequest builds a RunCommand request (opcode 0x1002).
//
// This library only implements the Unicode command-text path (CP 0x1104,
// UTF-16BE, requires server datastream level 10+ — in practice every IBM i
// release since V6R1/2008). The pre-level-10 path sends the command in the
// job's EBCDIC CCSID, which this library's restricted EBCDIC character set
// (letters/digits/space/$#@) cannot represent for realistic CL command
// syntax (parentheses, quotes, slashes are all common in command
// parameters) — so it's deliberately not implemented rather than shipped
// half-working.
func buildRunCommandRequest(command string, dsLevel uint16, msgOpt MessageOption) (as400.Request, error) {
	if dsLevel < 10 {
		return as400.Request{}, fmt.Errorf("rmtcmd: server datastream level %d is too old for this library's Unicode-only command path (needs 10+)", dsLevel)
	}
	cmdBytes := auth.UTF16BE(command)
	body := make([]byte, 11+len(cmdBytes))
	body[0] = remapMessageCount(dsLevel, msgOpt)
	binary.BigEndian.PutUint32(body[1:5], uint32(10+len(cmdBytes)))
	binary.BigEndian.PutUint16(body[5:7], 0x1104)
	binary.BigEndian.PutUint32(body[7:11], 1200) // CCSID of the command text: UTF-16BE
	copy(body[11:], cmdBytes)
	return as400.Request{ServerID: as400.ServerRemoteCommand, ReqRepID: 0x1002, TemplateLen: 1, Body: body}, nil
}

// ParamUsage selects a CallProgram parameter's direction.
type ParamUsage int

const (
	Input ParamUsage = iota
	Output
	InOut
	Null
)

// Parameter is one CallProgram argument. InputData is sent for Input/InOut
// parameters (trailing zero bytes are trimmed before sending, matching
// JTOpen's own behavior); OutputData is populated by CallProgram for
// Output/InOut parameters after a successful call.
type Parameter struct {
	Usage      ParamUsage
	MaxLength  int32
	InputData  []byte
	OutputData []byte
}

func trimTrailingZeros(b []byte) []byte {
	n := len(b)
	for n > 0 && b[n-1] == 0 {
		n--
	}
	return b[:n]
}

type resolvedParam struct {
	usage  uint16
	length int
	data   []byte
}

func resolveParam(p *Parameter, dsLevel uint16) resolvedParam {
	switch p.Usage {
	case Output:
		return resolvedParam{usage: 22}
	case Null:
		if dsLevel < 6 {
			return resolvedParam{usage: 1} // server predates NULL parameter support
		}
		return resolvedParam{usage: 0xFF}
	default: // Input, InOut
		data := trimTrailingZeros(p.InputData)
		usage := uint16(11)
		if p.Usage == InOut {
			if dsLevel >= 5 {
				usage = 33
			} else {
				usage = 13
			}
		}
		return resolvedParam{usage: usage, length: len(data), data: data}
	}
}

// buildCallProgramRequest builds a CallProgram request (opcode 0x1003).
// It does not implement JTOpen's optional RLE compression for large
// (>1024-byte) input parameters — always sending uncompressed input is
// still valid protocol, just less bandwidth-efficient for large payloads.
func buildCallProgramRequest(library, program string, params []*Parameter, dsLevel uint16, msgOpt MessageOption) (as400.Request, error) {
	progBytes, err := auth.EncodeEBCDICPadded(strings.ToUpper(program), 10)
	if err != nil {
		return as400.Request{}, fmt.Errorf("rmtcmd: program name: %w", err)
	}
	libBytes, err := auth.EncodeEBCDICPadded(strings.ToUpper(library), 10)
	if err != nil {
		return as400.Request{}, fmt.Errorf("rmtcmd: library name: %w", err)
	}

	resolved := make([]resolvedParam, len(params))
	bodyLen := 23
	for i, p := range params {
		resolved[i] = resolveParam(p, dsLevel)
		bodyLen += 12 + resolved[i].length
	}

	body := make([]byte, bodyLen)
	copy(body[0:10], progBytes)
	copy(body[10:20], libBytes)
	body[20] = remapMessageCount(dsLevel, msgOpt)
	binary.BigEndian.PutUint16(body[21:23], uint16(len(params)))

	idx := 23
	for i, e := range resolved {
		binary.BigEndian.PutUint32(body[idx:idx+4], uint32(e.length+12))
		binary.BigEndian.PutUint16(body[idx+4:idx+6], 0x1103)
		binary.BigEndian.PutUint32(body[idx+6:idx+10], uint32(params[i].MaxLength))
		binary.BigEndian.PutUint16(body[idx+10:idx+12], e.usage)
		if e.length > 0 {
			copy(body[idx+12:idx+12+e.length], e.data)
		}
		idx += 12 + e.length
	}

	return as400.Request{ServerID: as400.ServerRemoteCommand, ReqRepID: 0x1003, TemplateLen: 23, Body: body}, nil
}

// parseCallProgramOutput fills OutputData on each Output/InOut parameter
// from a successful CallProgram reply. A parameter entry is
// length(4)+code(2)+declaredLength(4)+usage(2)+data — declaredLength is the
// parameter's true (decompressed) length, which the RLE case needs since
// the wire data for it is shorter than that.
func parseCallProgramOutput(body []byte, params []*Parameter) error {
	idx := 4 // absolute offset 24, minus the 20-byte header
	for _, p := range params {
		if p.Usage != Output && p.Usage != InOut {
			continue
		}
		if p.MaxLength <= 0 {
			continue
		}
		if idx+12 > len(body) {
			return fmt.Errorf("rmtcmd: call-program reply truncated while reading output parameters")
		}
		byteLength := int(binary.BigEndian.Uint32(body[idx : idx+4]))
		declaredLength := int(binary.BigEndian.Uint32(body[idx+6 : idx+10]))
		usage := binary.BigEndian.Uint16(body[idx+10 : idx+12])
		if byteLength < 12 || idx+byteLength > len(body) {
			return fmt.Errorf("rmtcmd: call-program reply has an invalid parameter entry length")
		}
		raw := body[idx+12 : idx+byteLength]
		if usage == 22 || usage == 23 {
			decompressed, err := decompressRLE(raw, declaredLength)
			if err != nil {
				return err
			}
			p.OutputData = decompressed
		} else {
			p.OutputData = append([]byte(nil), raw...)
		}
		idx += byteLength
	}
	return nil
}
