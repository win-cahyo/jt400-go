package rmtcmd

import (
	"encoding/binary"
	"fmt"
)

// RunCommand runs a CL command string on the server and returns any
// messages attached to the reply (informational on success, diagnostic on
// failure). A non-nil error means the command did not complete
// successfully — inspect the returned messages for why.
func (c *Client) RunCommand(command string, msgOpt MessageOption) ([]Message, error) {
	req, err := buildRunCommandRequest(command, c.dsLevel, msgOpt)
	if err != nil {
		return nil, err
	}
	reply, err := c.conn.Call(req)
	if err != nil {
		return nil, fmt.Errorf("rmtcmd: run command: %w", err)
	}
	if len(reply.Body) < 2 {
		return nil, fmt.Errorf("rmtcmd: run-command reply too short")
	}
	rc := binary.BigEndian.Uint16(reply.Body[0:2])
	messages := parseMessages(reply.Body)
	if rc != 0 {
		return messages, &Error{RC: rc}
	}
	return messages, nil
}
