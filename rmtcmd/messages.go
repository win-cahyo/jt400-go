package rmtcmd

import (
	"encoding/binary"
	"strings"

	"jt400-go/as400/auth"
)

// Message is one IBM i message attached to a RunCommand/CallProgram reply
// (e.g. the CPFxxxx diagnostic explaining why a command failed).
//
// Message text/help/file-name/library-name are decoded with this library's
// restricted EBCDIC table (auth.DecodeEBCDICLossy) rather than a full
// CCSID converter, since message text can contain arbitrary characters;
// unmappable bytes become '?'. ID is almost always fully representable
// (message IDs are letters/digits, e.g. "CPF1234").
type Message struct {
	ID               string
	Type             int
	Severity         int
	Text             string
	Help             string
	FileName         string
	LibraryName      string
	SubstitutionData []byte
}

// parseMessages decodes the message list that follows a reply's return
// code, in whichever of the three wire formats JTOpen's
// RemoteCommandImplRemote.parseMessages supports (a format byte at each
// entry's offset+5 selects between them). body excludes the 20-byte
// datastream header — every offset below is shifted by -20 from the
// equivalent JTOpen source to account for that.
//
// Malformed input degrades to a truncated message list rather than a
// panic: message parsing is diagnostic, layered on top of the RC the
// caller already has, and a parsing edge case in three variably-shaped
// wire formats this library cannot test against a live server shouldn't
// take down an otherwise-successful call.
func parseMessages(body []byte) (messages []Message) {
	defer func() {
		if recover() != nil {
			// leave `messages` as whatever was appended so far
		}
	}()
	if len(body) < 4 {
		return nil
	}
	count := int(binary.BigEndian.Uint16(body[2:4]))
	off := 4
	for i := 0; i < count && off+6 <= len(body); i++ {
		format := body[off+5]
		switch format {
		case 0x06:
			messages = append(messages, parseMessage06(body, off+6))
		case 0x07:
			messages = append(messages, parseMessage07(body, off))
		default:
			messages = append(messages, parseMessageClassic(body, off))
		}
		if off+4 > len(body) {
			break
		}
		ll := int(binary.BigEndian.Uint32(body[off : off+4]))
		if ll <= 0 {
			break
		}
		off += ll
	}
	return messages
}

func safeSlice(b []byte, start, end int) []byte {
	if start < 0 || end > len(b) || start > end {
		return nil
	}
	return b[start:end]
}

// parseMessageClassic is the "else" branch of RemoteCommandImplRemote.
// parseMessages: a fixed layout starting at the entry itself (off).
func parseMessageClassic(body []byte, off int) Message {
	m := Message{}
	if off+37 <= len(body) {
		m.ID = strings.TrimRight(auth.DecodeEBCDICLossy(safeSlice(body, off+6, off+13)), " ")
		if off+15 <= len(body) {
			m.Type = int(body[off+13]&0x0F)*10 + int(body[off+14]&0x0F)
		}
		if sev := safeSlice(body, off+15, off+17); len(sev) == 2 {
			m.Severity = int(binary.BigEndian.Uint16(sev))
		}
		m.FileName = strings.TrimRight(auth.DecodeEBCDICLossy(safeSlice(body, off+17, off+27)), " ")
		m.LibraryName = strings.TrimRight(auth.DecodeEBCDICLossy(safeSlice(body, off+27, off+37)), " ")
	}
	if lenBytes := safeSlice(body, off+37, off+41); len(lenBytes) == 4 {
		subLen := int(binary.BigEndian.Uint16(lenBytes[0:2]))
		textLen := int(binary.BigEndian.Uint16(lenBytes[2:4]))
		p := off + 41
		if sub := safeSlice(body, p, p+subLen); sub != nil {
			m.SubstitutionData = append([]byte(nil), sub...)
		}
		p += subLen
		if text := safeSlice(body, p, p+textLen); text != nil {
			m.Text = auth.DecodeEBCDICLossy(text)
		}
	}
	return m
}

// fieldReader sequentially consumes the [4-byte length][that many bytes]
// fields used throughout the 0x06 and 0x07 message formats.
type fieldReader struct {
	body []byte
	off  int
}

func (r *fieldReader) bytes(n int) []byte {
	if n < 0 || r.off+n > len(r.body) {
		r.off = len(r.body)
		return nil
	}
	b := r.body[r.off : r.off+n]
	r.off += n
	return b
}

func (r *fieldReader) lenPrefixed() []byte {
	n4 := r.bytes(4)
	if len(n4) < 4 {
		return nil
	}
	return r.bytes(int(binary.BigEndian.Uint32(n4)))
}

// parseMessage06 mirrors AS400ImplRemote.parseMessage: fields start at
// `start` (the caller passes the entry's offset+6).
func parseMessage06(body []byte, start int) Message {
	r := &fieldReader{body: body, off: start}
	r.bytes(4) // text CCSID, not surfaced
	r.bytes(4) // substitution-data CCSID, not surfaced
	m := Message{}
	if sev := r.bytes(2); len(sev) == 2 {
		m.Severity = int(binary.BigEndian.Uint16(sev))
	}
	if t := r.lenPrefixed(); len(t) >= 2 {
		m.Type = int(t[0]&0x0F)*10 + int(t[1]&0x0F)
	}
	m.ID = strings.TrimRight(auth.DecodeEBCDICLossy(r.lenPrefixed()), " ")
	m.FileName = strings.TrimRight(auth.DecodeEBCDICLossy(r.lenPrefixed()), " ")
	m.LibraryName = strings.TrimRight(auth.DecodeEBCDICLossy(r.lenPrefixed()), " ")
	m.Text = auth.DecodeEBCDICLossy(r.lenPrefixed())
	m.SubstitutionData = append([]byte(nil), r.lenPrefixed()...)
	m.Help = auth.DecodeEBCDICLossy(r.lenPrefixed())
	return m
}

// parseMessage07 mirrors the extended-format branch inline in
// RemoteCommandImplRemote.parseMessages. Several fields (sending job
// identity, dates, receiving-program info) are consumed to stay aligned
// with the field sequence but not surfaced on Message, matching JTOpen's
// own choice not to store the always-blank sending-job fields.
func parseMessage07(body []byte, entryStart int) Message {
	r := &fieldReader{body: body, off: entryStart + 6}
	m := Message{}

	if sev := r.lenPrefixed(); len(sev) >= 4 {
		m.Severity = int(binary.BigEndian.Uint32(sev[:4]))
	}
	m.ID = strings.TrimRight(auth.DecodeEBCDICLossy(r.lenPrefixed()), " ")
	if t := r.lenPrefixed(); len(t) >= 2 {
		m.Type = int(t[0]&0x0F)*10 + int(t[1]&0x0F)
	}
	r.lenPrefixed() // message key
	m.FileName = strings.TrimRight(auth.DecodeEBCDICLossy(r.lenPrefixed()), " ")
	r.lenPrefixed() // message file library specified
	m.LibraryName = strings.TrimRight(auth.DecodeEBCDICLossy(r.lenPrefixed()), " ")
	r.lenPrefixed() // sending job (always blank per IBM's QMHRCVPM docs)
	r.lenPrefixed() // sending job user profile (always blank)
	r.lenPrefixed() // sending job number (always blank)
	r.lenPrefixed() // sending program name
	r.lenPrefixed() // sending program instruction number
	r.lenPrefixed() // date sent
	r.lenPrefixed() // time sent
	r.lenPrefixed() // receiving program name
	r.lenPrefixed() // receiving program instruction number
	r.lenPrefixed() // sending type
	r.lenPrefixed() // receiving type
	r.lenPrefixed() // text CCSID conversion status indicator
	r.lenPrefixed() // data CCSID conversion status indicator
	r.lenPrefixed() // alert option
	r.lenPrefixed() // message/help CCSID
	r.lenPrefixed() // substitution-data CCSID
	m.SubstitutionData = append([]byte(nil), r.lenPrefixed()...)
	m.Text = auth.DecodeEBCDICLossy(r.lenPrefixed()) // not trimmed, matching JTOpen
	m.Help = strings.TrimRight(auth.DecodeEBCDICLossy(r.lenPrefixed()), " ")
	return m
}
