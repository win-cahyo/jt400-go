package database

import (
	"errors"
	"fmt"
	"strings"
)

// Error is a failure reported by the as-database server.
type Error struct {
	// Op names the request that failed (e.g. "prepare", "execute").
	Op string
	// ErrorClass is the server's error class. Class 1 means an SQL error,
	// in which case ReturnCode is the SQLCODE; other classes are host
	// server errors (see the IBM i "Host server return codes"
	// documentation for the as-database server).
	ErrorClass int
	ReturnCode int
	// SQLState is the five-character SQLSTATE, when the reply carried an
	// SQLCA.
	SQLState string
	// MessageID and Message are the server's message (e.g. "SQL0204",
	// "X in Y type *FILE not found."), when it sent one.
	MessageID string
	Message   string
}

func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "database: %s failed", e.Op)
	if e.MessageID != "" {
		fmt.Fprintf(&b, ": [%s]", e.MessageID)
	}
	if e.Message != "" {
		fmt.Fprintf(&b, " %s", e.Message)
	}
	if e.ErrorClass == errorClassSQL {
		fmt.Fprintf(&b, " (SQLCODE %d", e.ReturnCode)
	} else {
		fmt.Fprintf(&b, " (error class %d, return code %d", e.ErrorClass, e.ReturnCode)
	}
	if e.SQLState != "" {
		fmt.Fprintf(&b, ", SQLSTATE %s", e.SQLState)
	}
	b.WriteString(")")
	return b.String()
}

// SQLCode returns the SQLCODE for an SQL error, or 0 for a host-server
// error that is not tied to an SQL statement.
func (e *Error) SQLCode() int {
	if e.ErrorClass == errorClassSQL {
		return e.ReturnCode
	}
	return 0
}

func newError(op string, r *reply) *Error {
	return &Error{
		Op:         op,
		ErrorClass: int(r.errorClass),
		ReturnCode: int(r.returnCode),
		SQLState:   strings.TrimSpace(r.sqlState()),
		MessageID:  strings.TrimSpace(r.messageID),
		Message:    strings.TrimSpace(r.message),
	}
}

// ErrConnBroken is returned for any use of a Conn after an I/O failure
// (including a cancelled context) left its datastream in an unknown state.
var ErrConnBroken = errors.New("database: connection is broken by an earlier I/O error and must be closed")

// ErrClosed is returned for use of a closed Conn, Stmt or Rows.
var ErrClosed = errors.New("database: use of closed connection, statement or rows")
