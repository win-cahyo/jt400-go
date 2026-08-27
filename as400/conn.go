package as400

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

// DialOptions configures how a Connection is established to an IBM i host
// server port (e.g. as-signon on 8476, as-dtaq on 8472, as-rmtcmd on 8475).
type DialOptions struct {
	// Host is the IBM i system's hostname or IP address.
	Host string
	// Port is the TCP port of the target host server.
	Port int
	// TLSConfig, if non-nil, upgrades the connection to TLS (the SSL
	// variant port for the target host server, e.g. 9476 for as-signon).
	TLSConfig *tls.Config
	// Timeout bounds the TCP (and TLS handshake, if any) dial. Zero means
	// no timeout.
	Timeout time.Duration
}

// Connection is a raw, established connection to a single IBM i host server
// port. Service packages (signon, dtaq, rmtcmd) build their datastream
// exchanges on top of this.
//
// A Connection handles one request at a time: Call writes a request and
// blocks for its reply. Concurrent Call invocations on the same Connection
// are not supported — this library does not implement the multi-request
// pipelining JTOpen's AS400ThreadedServer supports, since none of the three
// services targeted here need it.
type Connection struct {
	net.Conn

	mu          sync.Mutex
	correlation uint32
}

// Dial opens a TCP (or, if opts.TLSConfig is set, TLS) connection to an IBM
// i host server port. It does not perform any protocol handshake — that is
// the responsibility of the service-specific client (e.g. signon.Connect).
func Dial(opts DialOptions) (*Connection, error) {
	addr := net.JoinHostPort(opts.Host, fmt.Sprintf("%d", opts.Port))
	dialer := &net.Dialer{Timeout: opts.Timeout}

	var conn net.Conn
	var err error
	if opts.TLSConfig != nil {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, opts.TLSConfig)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("as400: dial %s: %w", addr, err)
	}
	return &Connection{Conn: conn}, nil
}

// Call writes req (after assigning it a fresh correlation ID) and returns
// the next reply datastream read from the connection.
func (c *Connection) Call(req Request) (*Reply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	req.Correlation = c.nextCorrelation()
	if _, err := c.Write(req.Encode()); err != nil {
		return nil, fmt.Errorf("as400: write request: %w", err)
	}
	return ReadReply(c)
}

// nextCorrelation mirrors AS400ThreadedServer.newCorrelationId(): a
// per-connection counter starting at 1, wrapping past the reserved value 0.
func (c *Connection) nextCorrelation() uint32 {
	c.correlation++
	if c.correlation == 0 {
		c.correlation = 1
	}
	return c.correlation
}
