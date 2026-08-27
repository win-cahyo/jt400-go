package rmtcmd

import "fmt"

// Error reports a non-success return code from the as-rmtcmd server. RC
// families follow RemoteCommandImplRemote.processReturnCode.
type Error struct {
	RC uint16
}

func (e *Error) Error() string {
	switch {
	case e.RC == 0x0400:
		return fmt.Sprintf("rmtcmd: command failed (rc=%#04x); see the returned message list", e.RC)
	case e.RC == 0x0401:
		return fmt.Sprintf("rmtcmd: invalid CCSID (rc=%#04x)", e.RC)
	case e.RC == 0x0500:
		return fmt.Sprintf("rmtcmd: program could not be resolved (rc=%#04x)", e.RC)
	case e.RC == 0x0501:
		return fmt.Sprintf("rmtcmd: program call error (rc=%#04x); see the returned message list", e.RC)
	case e.RC >= 0x0100 && e.RC < 0x0200:
		return fmt.Sprintf("rmtcmd: exchange-attributes error (rc=%#04x)", e.RC)
	case e.RC >= 0x0200 && e.RC < 0x0300:
		return fmt.Sprintf("rmtcmd: protocol error (rc=%#04x)", e.RC)
	case e.RC >= 0x0300 && e.RC < 0x0400:
		return fmt.Sprintf("rmtcmd: exit program error (rc=%#04x)", e.RC)
	default:
		return fmt.Sprintf("rmtcmd: request failed (rc=%#04x)", e.RC)
	}
}
