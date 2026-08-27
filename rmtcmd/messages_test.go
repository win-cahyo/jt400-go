package rmtcmd

import (
	"encoding/binary"
	"testing"

	"jt400-go/as400/auth"
)

func be32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func lenPrefixedField(data []byte) []byte {
	return append(be32(uint32(len(data))), data...)
}

func mustEBCDICBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := auth.EncodeEBCDIC(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// wrapMessageList builds the [count(2)][entries...] structure parseMessages
// expects, given already-built entry bytes (each entry's own leading LL is
// added here).
func wrapMessageList(entries ...[]byte) []byte {
	header := make([]byte, 4) // body[0:2] unused by parseMessages, body[2:4] = count
	binary.BigEndian.PutUint16(header[2:4], uint16(len(entries)))
	body := header
	for _, e := range entries {
		entry := append(be32(uint32(4+len(e))), e...)
		body = append(body, entry...)
	}
	return body
}

func TestParseMessagesClassicFormat(t *testing.T) {
	id := mustEBCDICBytes(t, "CPF1234")
	fileName, err := auth.EncodeEBCDICPadded("MYMSGF", 10)
	if err != nil {
		t.Fatal(err)
	}
	libName, err := auth.EncodeEBCDICPadded("MYLIB", 10)
	if err != nil {
		t.Fatal(err)
	}
	text := mustEBCDICBytes(t, "SOME ERROR TEXT")

	// entry (post-LL) layout: [format@+1][id(7)@+2..8][type(2)@+9..10][sev(2)@+11..12][file(10)][lib(10)][subLen(2)][textLen(2)][sub][text]
	entry := make([]byte, 2)
	entry[1] = 0x00                   // format byte (offset+5 relative to entry start = index 1 here, since we prepend LL separately)
	entry = append(entry, id...)      // +6..12 (7 bytes)
	entry = append(entry, 0xF1, 0xF0) // +13,+14: type "10"
	sev := make([]byte, 2)
	binary.BigEndian.PutUint16(sev, 30)
	entry = append(entry, sev...)      // +15,16
	entry = append(entry, fileName...) // +17..26
	entry = append(entry, libName...)  // +27..36
	subLen := make([]byte, 2)
	textLen := make([]byte, 2)
	binary.BigEndian.PutUint16(textLen, uint16(len(text)))
	entry = append(entry, subLen...)
	entry = append(entry, textLen...)
	entry = append(entry, text...)

	body := wrapMessageList(entry)
	messages := parseMessages(body)
	if len(messages) != 1 {
		t.Fatalf("got %d messages, want 1", len(messages))
	}
	m := messages[0]
	if m.ID != "CPF1234" {
		t.Errorf("ID = %q, want %q", m.ID, "CPF1234")
	}
	if m.Type != 10 {
		t.Errorf("Type = %d, want 10", m.Type)
	}
	if m.Severity != 30 {
		t.Errorf("Severity = %d, want 30", m.Severity)
	}
	if m.FileName != "MYMSGF" {
		t.Errorf("FileName = %q, want %q", m.FileName, "MYMSGF")
	}
	if m.LibraryName != "MYLIB" {
		t.Errorf("LibraryName = %q, want %q", m.LibraryName, "MYLIB")
	}
	if m.Text != "SOME ERROR TEXT" {
		t.Errorf("Text = %q, want %q", m.Text, "SOME ERROR TEXT")
	}
}

func TestParseMessages06Format(t *testing.T) {
	id := mustEBCDICBytes(t, "CPF9999")
	text := mustEBCDICBytes(t, "ANOTHER ERROR")

	var fields []byte
	fields = append(fields, be32(0)...) // text CCSID length+val placeholder, consumed as 4 raw bytes
	fields = append(fields, be32(0)...) // substitution CCSID
	sev := make([]byte, 2)
	binary.BigEndian.PutUint16(sev, 40)
	fields = append(fields, sev...)
	fields = append(fields, lenPrefixedField([]byte{0xF0, 0xF5})...) // type "05"
	fields = append(fields, lenPrefixedField(id)...)
	fields = append(fields, lenPrefixedField(nil)...) // file name
	fields = append(fields, lenPrefixedField(nil)...) // library name
	fields = append(fields, lenPrefixedField(text)...)
	fields = append(fields, lenPrefixedField(nil)...) // substitution data
	fields = append(fields, lenPrefixedField(nil)...) // help

	entry := append([]byte{0x00, 0x06}, fields...) // format byte at index 1 (offset+5 relative to entry start=index0... see note below)
	body := wrapMessageList(entry)
	messages := parseMessages(body)
	if len(messages) != 1 {
		t.Fatalf("got %d messages, want 1", len(messages))
	}
	m := messages[0]
	if m.ID != "CPF9999" {
		t.Errorf("ID = %q, want %q", m.ID, "CPF9999")
	}
	if m.Type != 5 {
		t.Errorf("Type = %d, want 5", m.Type)
	}
	if m.Severity != 40 {
		t.Errorf("Severity = %d, want 40", m.Severity)
	}
	if m.Text != "ANOTHER ERROR" {
		t.Errorf("Text = %q, want %q", m.Text, "ANOTHER ERROR")
	}
}

func TestParseMessages07Format(t *testing.T) {
	id := mustEBCDICBytes(t, "CPF3333")
	fileName := mustEBCDICBytes(t, "MSGF")
	libName := mustEBCDICBytes(t, "QSYS")
	sendingProgram := mustEBCDICBytes(t, "MYPGM")
	text := mustEBCDICBytes(t, "SEVENTH FORMAT ERROR")
	help := mustEBCDICBytes(t, "SOME HELP TEXT")

	sevBytes := be32(50)

	var fields []byte
	fields = append(fields, lenPrefixedField(sevBytes)...)                       // severity
	fields = append(fields, lenPrefixedField(id)...)                             // message ID
	fields = append(fields, lenPrefixedField([]byte{0xF0, 0xF2})...)             // type "02"
	fields = append(fields, lenPrefixedField([]byte{0xAA, 0xBB, 0xCC, 0xDD})...) // message key
	fields = append(fields, lenPrefixedField(fileName)...)                       // file name
	fields = append(fields, lenPrefixedField(nil)...)                            // file library specified
	fields = append(fields, lenPrefixedField(libName)...)                        // library used
	fields = append(fields, lenPrefixedField(nil)...)                            // sending job
	fields = append(fields, lenPrefixedField(nil)...)                            // sending job user profile
	fields = append(fields, lenPrefixedField(nil)...)                            // sending job number
	fields = append(fields, lenPrefixedField(sendingProgram)...)                 // sending program name
	fields = append(fields, lenPrefixedField(nil)...)                            // sending program instruction number
	fields = append(fields, lenPrefixedField(nil)...)                            // date sent
	fields = append(fields, lenPrefixedField(nil)...)                            // time sent
	fields = append(fields, lenPrefixedField(nil)...)                            // receiving program name
	fields = append(fields, lenPrefixedField(nil)...)                            // receiving program instruction number
	fields = append(fields, lenPrefixedField(nil)...)                            // sending type
	fields = append(fields, lenPrefixedField(nil)...)                            // receiving type
	fields = append(fields, lenPrefixedField(be32(0))...)                        // text CCSID conversion status
	fields = append(fields, lenPrefixedField(be32(0))...)                        // data CCSID conversion status
	fields = append(fields, lenPrefixedField(nil)...)                            // alert option
	fields = append(fields, lenPrefixedField(be32(37))...)                       // message/help CCSID
	fields = append(fields, lenPrefixedField(be32(37))...)                       // substitution-data CCSID
	fields = append(fields, lenPrefixedField(nil)...)                            // substitution data
	fields = append(fields, lenPrefixedField(text)...)                           // text
	fields = append(fields, lenPrefixedField(help)...)                           // help

	entry := append([]byte{0x00, 0x07}, fields...)
	body := wrapMessageList(entry)
	messages := parseMessages(body)
	if len(messages) != 1 {
		t.Fatalf("got %d messages, want 1", len(messages))
	}
	m := messages[0]
	if m.ID != "CPF3333" {
		t.Errorf("ID = %q, want %q", m.ID, "CPF3333")
	}
	if m.Type != 2 {
		t.Errorf("Type = %d, want 2", m.Type)
	}
	if m.Severity != 50 {
		t.Errorf("Severity = %d, want 50", m.Severity)
	}
	if m.FileName != "MSGF" {
		t.Errorf("FileName = %q, want %q", m.FileName, "MSGF")
	}
	if m.LibraryName != "QSYS" {
		t.Errorf("LibraryName = %q, want %q", m.LibraryName, "QSYS")
	}
	if m.Text != "SEVENTH FORMAT ERROR" {
		t.Errorf("Text = %q, want %q", m.Text, "SEVENTH FORMAT ERROR")
	}
	if m.Help != "SOME HELP TEXT" {
		t.Errorf("Help = %q, want %q", m.Help, "SOME HELP TEXT")
	}
}
