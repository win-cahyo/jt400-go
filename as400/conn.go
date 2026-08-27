package as400

import (
	"crypto/tls"
	"fmt"
	"net"
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
type Connection struct {
	net.Conn
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
