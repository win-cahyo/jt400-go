package signon

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"jt400-go/as400"
)

// Client is a connection to an as-signon host server that has completed
// the exchange-attributes handshake and is ready for Authenticate.
type Client struct {
	conn        *as400.Connection
	clientSeed  [8]byte
	serverSeed  [8]byte
	passwordLvl PasswordLevel
	serverLevel uint16
	jobName     string
}

// Connect dials the as-signon host server (plain port 8476 by default, or
// the SSL port 9476 when opts.TLSConfig is set) and performs the
// exchange-attributes handshake. It does not authenticate — call
// Authenticate on the result next.
func Connect(opts as400.DialOptions) (*Client, error) {
	if opts.Port == 0 {
		if opts.TLSConfig != nil {
			opts.Port = as400.PortSignonSecure
		} else {
			opts.Port = as400.PortSignonPlain
		}
	}
	conn, err := as400.Dial(opts)
	if err != nil {
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
	var seed [8]byte
	binary.BigEndian.PutUint64(seed[:], uint64(time.Now().UnixMilli()))

	reply, err := c.conn.Call(buildExchangeAttributeRequest(seed))
	if err != nil {
		return fmt.Errorf("signon: exchange attributes: %w", err)
	}
	attrs, err := parseExchangeAttributeReply(reply)
	if err != nil {
		return err
	}
	c.clientSeed = seed
	c.serverSeed = attrs.ServerSeed
	c.passwordLvl = attrs.PasswordLevel
	c.serverLevel = attrs.ServerLevel
	c.jobName = attrs.JobName
	return nil
}

// Authenticate signs on with userID/password, encrypting the password
// according to the password level negotiated during Connect.
func (c *Client) Authenticate(userID, password string) (*SignonInfo, error) {
	authBytes, err := encryptPassword(c.passwordLvl, userID, password, c.clientSeed, c.serverSeed)
	if err != nil {
		return nil, err
	}
	userIDBytes, err := encodeEBCDIC10(strings.ToUpper(userID))
	if err != nil {
		return nil, fmt.Errorf("signon: user id: %w", err)
	}

	reply, err := c.conn.Call(buildSignonInfoRequest(userIDBytes, authBytes, c.serverLevel))
	if err != nil {
		return nil, fmt.Errorf("signon: authenticate: %w", err)
	}
	return parseSignonInfoReply(reply)
}

// PasswordLevel returns the password level negotiated during Connect. This
// determines which password-encryption scheme Authenticate uses, and is
// also what dtaq/rmtcmd connections need to perform their own start-server
// handshake against the same credentials.
func (c *Client) PasswordLevel() PasswordLevel { return c.passwordLvl }

// ClientSeed and ServerSeed return the seeds exchanged during Connect.
func (c *Client) ClientSeed() [8]byte { return c.clientSeed }
func (c *Client) ServerSeed() [8]byte { return c.serverSeed }

// Close closes the underlying connection.
func (c *Client) Close() error { return c.conn.Close() }
