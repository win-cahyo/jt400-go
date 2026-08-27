package signon

import "fmt"

// signonRCMessages maps the return codes most likely to occur during a
// normal authentication attempt to a human-readable reason, from
// AS400ImplRemote.returnSecurityException's RC switch.
var signonRCMessages = map[uint32]string{
	0x00020001: "unknown user ID",
	0x00020002: "user profile disabled",
	0x00020003: "user ID does not match what the server expected",
	0x0003000B: "incorrect password",
	0x0003000C: "incorrect password; profile will be disabled if repeated",
	0x0003000D: "password expired",
	0x0003000E: "password not valid for a system at this encryption level",
}

// AuthError reports a non-zero return code from the as-signon server.
type AuthError struct {
	RC uint32
}

func (e *AuthError) Error() string {
	if msg, ok := signonRCMessages[e.RC]; ok {
		return fmt.Sprintf("signon: %s (rc=%#08x)", msg, e.RC)
	}
	return fmt.Sprintf("signon: authentication failed, rc=%#08x", e.RC)
}

func signonError(rc uint32) error {
	return &AuthError{RC: rc}
}
