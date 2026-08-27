package rmtcmd

import (
	"encoding/binary"
	"fmt"
)

// CallProgram calls program/library with params, populating each
// Output/InOut parameter's OutputData on success. It returns any messages
// attached to the reply; a non-nil error means the call did not complete
// successfully — inspect the returned messages for why.
func (c *Client) CallProgram(library, program string, params []*Parameter, msgOpt MessageOption) ([]Message, error) {
	req, err := buildCallProgramRequest(library, program, params, c.dsLevel, msgOpt)
	if err != nil {
		return nil, err
	}
	reply, err := c.conn.Call(req)
	if err != nil {
		return nil, fmt.Errorf("rmtcmd: call program: %w", err)
	}
	if len(reply.Body) < 2 {
		return nil, fmt.Errorf("rmtcmd: call-program reply too short")
	}
	rc := binary.BigEndian.Uint16(reply.Body[0:2])
	messages := parseMessages(reply.Body)
	if rc != 0 {
		return messages, &Error{RC: rc}
	}
	if err := parseCallProgramOutput(reply.Body, params); err != nil {
		return messages, err
	}
	return messages, nil
}
