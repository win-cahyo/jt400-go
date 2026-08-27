package dtaq

import "fmt"

// rcMessages maps as-dtaq return codes (DQCommonReplyDataStream, a 16-bit
// field — narrower than the 32-bit RC used by as-signon/as400.Logon) to a
// human-readable reason.
var rcMessages = map[uint16]string{
	0xF002: "protocol error",
	0xF003: "syntax error",
	0xF004: "queue destroyed",
	0xF005: "unsupported entry or queue length",
	0xF006: "no data available",
	0xF007: "invalid data stream level",
	0xF008: "invalid VRM",
	0xF009: "rejected by exit program",
	0xF00A: "exit program not authorized",
	0xF00B: "exit program not found",
	0xF00D: "exit program failed",
	0xF00E: "invalid number of exit programs",
}

// cpfMessages maps the CPF message IDs that accompany RC 0xF001 ("command
// check") to a human-readable reason.
var cpfMessages = map[string]string{
	"CPF9810": "library not found",
	"CPF9801": "object not found",
	"CPF2105": "object not found",
	"CPF9802": "object authority insufficient",
	"CPF2189": "object authority insufficient",
	"CPF9820": "library authority insufficient",
	"CPF2182": "library authority insufficient",
	"CPF9870": "object already exists",
	"CPF9502": "queue is not a keyed data queue",
	"CPF9506": "queue is a keyed data queue",
}

// Error reports a non-success return code from the as-dtaq server.
type Error struct {
	RC        uint16
	MessageID string
	Message   string
}

func (e *Error) Error() string {
	if e.MessageID != "" {
		if desc, ok := cpfMessages[e.MessageID]; ok {
			return fmt.Sprintf("dtaq: %s: %s (rc=%#04x)", e.MessageID, desc, e.RC)
		}
		return fmt.Sprintf("dtaq: %s: %s (rc=%#04x)", e.MessageID, e.Message, e.RC)
	}
	if desc, ok := rcMessages[e.RC]; ok {
		return fmt.Sprintf("dtaq: %s (rc=%#04x)", desc, e.RC)
	}
	return fmt.Sprintf("dtaq: request failed, rc=%#04x", e.RC)
}
