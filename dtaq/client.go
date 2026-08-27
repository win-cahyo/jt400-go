package dtaq

import (
	"fmt"

	"jt400-go/as400"
)

// Client is an authenticated connection to an as-dtaq host server.
type Client struct {
	conn *as400.Connection
}

// Connect dials the as-dtaq host server (plain port 8472 by default, or
// the SSL port 9472 when opts.TLSConfig is set), performs the generic
// host-server logon (see as400.Logon), and the dtaq-specific exchange-
// attributes handshake required before any other request.
func Connect(opts as400.DialOptions, userID, password string) (*Client, error) {
	if opts.Port == 0 {
		if opts.TLSConfig != nil {
			opts.Port = as400.PortDataQueueSecure
		} else {
			opts.Port = as400.PortDataQueuePlain
		}
	}
	conn, err := as400.Dial(opts)
	if err != nil {
		return nil, err
	}
	if _, err := as400.Logon(conn, as400.ServerDataQueue, userID, password); err != nil {
		conn.Close()
		return nil, err
	}
	c := &Client{conn: conn}
	if err := c.exchangeAttributes(); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

func (c *Client) exchangeAttributes() error {
	reply, err := c.conn.Call(buildExchangeAttributesRequest())
	if err != nil {
		return fmt.Errorf("dtaq: exchange attributes: %w", err)
	}
	if reply.ReqRepID == 0x8002 {
		return checkCommonReply(reply)
	}
	return nil
}

// Queue returns a handle for the named data queue (library/name), which
// need not exist yet — Create makes it.
func (c *Client) Queue(library, name string) *Queue {
	return &Queue{client: c, library: library, name: name}
}

// Close closes the underlying connection.
func (c *Client) Close() error { return c.conn.Close() }
