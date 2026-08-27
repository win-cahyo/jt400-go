package dtaq

import (
	"encoding/binary"
	"strings"

	"fmt"

	"jt400-go/as400"
	"jt400-go/as400/auth"
)

// SearchType selects how ReadKeyed matches its key against entries on a
// keyed data queue. The wire value is the literal 2-character EBCDIC code,
// not a numeric enum.
type SearchType string

const (
	SearchEQ SearchType = "EQ"
	SearchNE SearchType = "NE"
	SearchLT SearchType = "LT"
	SearchLE SearchType = "LE"
	SearchGT SearchType = "GT"
	SearchGE SearchType = "GE"
)

// PublicAuthority mirrors the *ALL/*CHANGE/*EXCLUDE/*USE/*LIBCRTAUT choices
// available when creating a queue.
type PublicAuthority byte

const (
	AuthorityUse       PublicAuthority = 0xF3
	AuthorityAll       PublicAuthority = 0xF0
	AuthorityChange    PublicAuthority = 0xF1
	AuthorityExclude   PublicAuthority = 0xF2
	AuthorityLibCrtAut PublicAuthority = 0xF4
)

func flagByte(b bool) byte {
	if b {
		return 0xF1
	}
	return 0xF0
}

// queueLibraryBytes encodes the 20-byte queue-name(10)+library(10) field
// every dtaq request opens with.
func queueLibraryBytes(library, name string) ([]byte, error) {
	q, err := auth.EncodeEBCDICPadded(strings.ToUpper(name), 10)
	if err != nil {
		return nil, fmt.Errorf("dtaq: queue name: %w", err)
	}
	lib, err := auth.EncodeEBCDICPadded(strings.ToUpper(library), 10)
	if err != nil {
		return nil, fmt.Errorf("dtaq: library name: %w", err)
	}
	out := make([]byte, 20)
	copy(out[0:10], q)
	copy(out[10:20], lib)
	return out, nil
}

func buildQueueOnlyRequest(reqRepID uint16, library, name string) (as400.Request, error) {
	body, err := queueLibraryBytes(library, name)
	if err != nil {
		return as400.Request{}, err
	}
	return as400.Request{ServerID: as400.ServerDataQueue, ReqRepID: reqRepID, TemplateLen: 20, Body: body}, nil
}

// buildExchangeAttributesRequest builds the dtaq-specific exchange-
// attributes request (opcode 0x0000 — distinct from the generic host-server
// exchange-random-seed request as400.Logon performs first). It must be sent
// once per connection before any other dtaq request.
func buildExchangeAttributesRequest() as400.Request {
	body := make([]byte, 6)
	binary.BigEndian.PutUint32(body[0:4], 1) // client version: supports 64K data queues
	return as400.Request{ServerID: as400.ServerDataQueue, ReqRepID: 0x0000, TemplateLen: 6, Body: body}
}

// CreateOptions configures Queue.Create.
type CreateOptions struct {
	MaxEntryLength          int32
	PublicAuthority         PublicAuthority
	SaveSenderInformation   bool
	Keyed                   bool
	KeyLength               int16 // only meaningful when Keyed is true
	FIFO                    bool  // only meaningful when Keyed is false; false means LIFO
	ForceToAuxiliaryStorage bool
	TextDescription         string
}

func buildCreateRequest(library, name string, opts CreateOptions) (as400.Request, error) {
	ql, err := queueLibraryBytes(library, name)
	if err != nil {
		return as400.Request{}, err
	}
	textBytes, err := auth.EncodeEBCDICPadded(opts.TextDescription, 50)
	if err != nil {
		return as400.Request{}, fmt.Errorf("dtaq: text description: %w", err)
	}

	pubAuth := opts.PublicAuthority
	if pubAuth == 0 {
		pubAuth = AuthorityUse
	}

	body := make([]byte, 80)
	copy(body[0:20], ql)
	binary.BigEndian.PutUint32(body[20:24], uint32(opts.MaxEntryLength))
	body[24] = byte(pubAuth)
	body[25] = flagByte(opts.SaveSenderInformation)
	switch {
	case opts.Keyed:
		body[26] = 0xF2
	case opts.FIFO:
		body[26] = 0xF0
	default:
		body[26] = 0xF1
	}
	keyLength := opts.KeyLength
	if !opts.Keyed {
		keyLength = 0
	}
	binary.BigEndian.PutUint16(body[27:29], uint16(keyLength))
	body[29] = flagByte(opts.ForceToAuxiliaryStorage)
	copy(body[30:80], textBytes)

	return as400.Request{ServerID: as400.ServerDataQueue, ReqRepID: 0x0003, TemplateLen: 80, Body: body}, nil
}

func buildClearRequest(library, name string, key []byte, hasKey bool) (as400.Request, error) {
	ql, err := queueLibraryBytes(library, name)
	if err != nil {
		return as400.Request{}, err
	}
	body := append(append([]byte{}, ql...), flagByte(hasKey))
	if hasKey {
		body = append(body, as400.EncodeParams(as400.Param{CodePoint: 0x5002, Data: key})...)
	}
	return as400.Request{ServerID: as400.ServerDataQueue, ReqRepID: 0x0006, TemplateLen: 21, Body: body}, nil
}

func buildWriteRequest(library, name string, key, entry []byte) (as400.Request, error) {
	ql, err := queueLibraryBytes(library, name)
	if err != nil {
		return as400.Request{}, err
	}
	body := append(append([]byte{}, ql...), flagByte(key != nil), 0x01)
	body = append(body, as400.EncodeParams(as400.Param{CodePoint: 0x5001, Data: entry})...)
	if key != nil {
		body = append(body, as400.EncodeParams(as400.Param{CodePoint: 0x5002, Data: key})...)
	}
	return as400.Request{ServerID: as400.ServerDataQueue, ReqRepID: 0x0005, TemplateLen: 22, Body: body}, nil
}

func buildReadRequest(library, name string, keyed bool, searchType SearchType, key []byte, waitSeconds int32, peek bool) (as400.Request, error) {
	ql, err := queueLibraryBytes(library, name)
	if err != nil {
		return as400.Request{}, err
	}
	body := make([]byte, 28)
	copy(body[0:20], ql)
	body[20] = flagByte(keyed)
	if keyed {
		st, err := auth.EncodeEBCDIC(string(searchType))
		if err != nil {
			return as400.Request{}, fmt.Errorf("dtaq: search type: %w", err)
		}
		if len(st) != 2 {
			return as400.Request{}, fmt.Errorf("dtaq: search type must be exactly 2 characters, got %q", searchType)
		}
		copy(body[21:23], st)
	}
	binary.BigEndian.PutUint32(body[23:27], uint32(waitSeconds))
	body[27] = flagByte(peek)
	if keyed {
		body = append(body, as400.EncodeParams(as400.Param{CodePoint: 0x5002, Data: key})...)
	}
	return as400.Request{ServerID: as400.ServerDataQueue, ReqRepID: 0x0002, TemplateLen: 28, Body: body}, nil
}

// checkCommonReply interprets a DQCommonReplyDataStream-shaped reply body
// (2-byte RC, optionally followed by an LL/CP-wrapped CPF message), used
// for create/delete/clear/write and as the error-path shape for
// exchange-attributes/attributes/read.
func checkCommonReply(reply *as400.Reply) error {
	if len(reply.Body) < 2 {
		return fmt.Errorf("dtaq: reply too short to contain a return code")
	}
	rc := binary.BigEndian.Uint16(reply.Body[0:2])
	if rc == 0xF000 {
		return nil
	}
	dtaqErr := &Error{RC: rc}
	if len(reply.Body) >= 8 {
		ll := binary.BigEndian.Uint32(reply.Body[2:6])
		msgLen := int(ll) - 6
		if msgLen > 0 && 8+msgLen <= len(reply.Body) {
			msg := reply.Body[8 : 8+msgLen]
			if len(msg) >= 9 {
				dtaqErr.MessageID = strings.TrimRight(auth.DecodeEBCDICLossy(msg[:7]), " ")
				dtaqErr.Message = auth.DecodeEBCDICLossy(msg[9:])
			}
		}
	}
	return dtaqErr
}

// Entry is one data queue entry, returned by Queue.Read/ReadKeyed.
type Entry struct {
	Data []byte
	// Key is only populated by ReadKeyed.
	Key []byte
	// SenderInformation is the opaque 36-byte sender-identification block
	// returned when the queue was created with SaveSenderInformation, or
	// nil otherwise. JTOpen itself never decomposes this block's internal
	// layout, so neither does this library.
	SenderInformation []byte
}

func parseReadReply(reply *as400.Reply) (*Entry, error) {
	switch reply.ReqRepID {
	case 0x8002:
		if err := checkCommonReply(reply); err != nil {
			if dtaqErr, ok := err.(*Error); ok && dtaqErr.RC == 0xF006 {
				return nil, nil // no entry available
			}
			return nil, err
		}
		return nil, nil
	case 0x8003:
		if len(reply.Body) < 38 {
			return nil, fmt.Errorf("dtaq: read reply missing fixed fields")
		}
		entry := &Entry{}
		sender := reply.Body[2:38]
		if sender[0] != 0x40 {
			entry.SenderInformation = append([]byte(nil), sender...)
		}
		params, err := as400.DecodeParams(reply.Body[38:])
		if err != nil {
			return nil, fmt.Errorf("dtaq: decode read reply: %w", err)
		}
		if d, ok := as400.Find(params, 0x5001); ok {
			entry.Data = append([]byte(nil), d...)
		}
		if d, ok := as400.Find(params, 0x5002); ok {
			entry.Key = append([]byte(nil), d...)
		}
		return entry, nil
	default:
		return nil, fmt.Errorf("dtaq: unexpected reply opcode %#x for read", reply.ReqRepID)
	}
}

// Attributes is a queue's configuration, returned by Queue.Attributes.
type Attributes struct {
	MaxEntryLength          int32
	SaveSenderInformation   bool
	Keyed                   bool
	FIFO                    bool // only meaningful when Keyed is false
	KeyLength               int16
	ForceToAuxiliaryStorage bool
	TextDescription         string
}

func parseAttributesReply(reply *as400.Reply) (*Attributes, error) {
	switch reply.ReqRepID {
	case 0x8002:
		return nil, checkCommonReply(reply)
	case 0x8001:
		if len(reply.Body) < 61 {
			return nil, fmt.Errorf("dtaq: attributes reply missing fixed fields")
		}
		qType := reply.Body[7] & 0x0F
		return &Attributes{
			MaxEntryLength:          int32(binary.BigEndian.Uint32(reply.Body[2:6])),
			SaveSenderInformation:   reply.Body[6] == 0xF1,
			Keyed:                   qType == 2,
			FIFO:                    qType == 0,
			KeyLength:               int16(binary.BigEndian.Uint16(reply.Body[8:10])),
			ForceToAuxiliaryStorage: reply.Body[10] == 0xF1,
			TextDescription:         strings.TrimRight(auth.DecodeEBCDICLossy(reply.Body[11:61]), " "),
		}, nil
	default:
		return nil, fmt.Errorf("dtaq: unexpected reply opcode %#x for attributes", reply.ReqRepID)
	}
}
