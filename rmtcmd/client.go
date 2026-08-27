package rmtcmd

import (
	"fmt"

	"jt400-go/as400"
)

// Client is an authenticated connection to an as-rmtcmd host server.
type Client struct {
	conn    *as400.Connection
	dsLevel uint16
	ccsid   uint32
}

// Connect dials the as-rmtcmd host server (plain port 8475 by default, or
// the SSL port 9475 when opts.TLSConfig is set), performs the generic
// host-server logon (see as400.Logon), and the rmtcmd-specific exchange-
// attributes handshake required before RunCommand/CallProgram.
func Connect(opts as400.DialOptions, userID, password string) (*Client, error) {
	if opts.Port == 0 {
		if opts.TLSConfig != nil {
			opts.Port = as400.PortRemoteCommandSecure
		} else {
			opts.Port = as400.PortRemoteCommandPlain
		}
	}
	conn, err := as400.Dial(opts)
	if err != nil {
		return nil, err
	}
	if _, err := as400.Logon(conn, as400.ServerRemoteCommand, userID, password); err != nil {
		conn.Close()
		return nil, err
	}

	reply, err := conn.Call(buildExchangeAttributesRequest())
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("rmtcmd: exchange attributes: %w", err)
	}
	ccsid, dsLevel, err := parseExchangeAttributesReply(reply)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &Client{conn: conn, dsLevel: dsLevel, ccsid: ccsid}, nil
}

// Close closes the underlying connection.
func (c *Client) Close() error { return c.conn.Close() }
