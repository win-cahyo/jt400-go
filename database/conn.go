package database

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/win-cahyo/jt400-go/as400"
	"github.com/win-cahyo/jt400-go/as400/auth"
)

// Options configures the SQL environment of a connection.
type Options struct {
	// SystemNaming selects system naming (LIB/FILE, unqualified names
	// resolved through the job's library list) instead of the default SQL
	// naming (SCHEMA.TABLE, unqualified names resolved against
	// DefaultSchema or the user profile name).
	SystemNaming bool
	// DefaultSchema, if set, is the default schema (library) for
	// unqualified names. Empty leaves the server's default.
	DefaultSchema string
	// Location is the time zone DATE and TIMESTAMP values are read in and
	// time.Time parameters are converted to before being sent. IBM i date
	// and time columns carry no zone of their own. Defaults to time.UTC.
	Location *time.Location
	// BlockSize is the approximate size in bytes of each block of rows
	// fetched from an open cursor. Defaults to 32 KB, JTOpen's
	// "block size" default.
	BlockSize int
}

// Isolation is a commitment control level, as set by Conn.Begin.
type Isolation int

// Commitment control levels (JDTransactionManager.COMMIT_MODE_*). A
// transaction needs the tables it changes to be journaled; on an
// unjournaled table, the server rejects the change (SQL7008).
const (
	IsolationNone            Isolation = 0 // *NONE: no commitment control
	IsolationReadUncommitted Isolation = 1 // *CHG
	IsolationReadCommitted   Isolation = 2 // *CS
	IsolationRepeatableRead  Isolation = 3 // *ALL
	IsolationSerializable    Isolation = 4 // *RR
)

const (
	// maxStatements is JTOpen's AS400JDBCConnectionImpl.MAX_STATEMENTS_:
	// RPB handles 1..9999 are available to statements; handle 0 is the
	// connection's own (for attributes, commit and rollback).
	maxStatements = 9999

	defaultBlockSize = 32 * 1024

	// clientFunctionalLevel is the value JTOpen sends as
	// AS400JDBCConnectionImpl.CLIENT_FUNCTIONAL_LEVEL_.
	clientFunctionalLevel = "V7R2M01   "
	// languageFeatureCode is the NLV for English, JTOpen's default.
	languageFeatureCode = "2924"

	vrmV5R4 = 5<<16 | 4<<8
)

// Conn is one authenticated as-database connection: a single server job
// with its own SQL environment. A Conn (and the Stmts and Rows made from
// it) is not safe for concurrent use; database/sql guarantees that for the
// driver, and direct users must serialize access themselves.
type Conn struct {
	conn *as400.Connection
	opts Options

	// Server facts learned from the set-attributes reply.
	serverCCSID     int
	vrm             int
	functionalLevel int
	jobID           string

	ids    [maxStatements + 1]bool
	inTx   bool
	broken bool
	closed bool
}

// Connect dials the as-database host server (plain port 8471 by default,
// or the SSL port 9471 when dial.TLSConfig is set), performs the generic
// host-server logon (see as400.Logon) and sets the SQL attributes the rest
// of this package depends on (ISO dates and times, extended data formats,
// autocommit with no commitment control).
//
// Set dial.IOTimeout to bound every request: without it, a host server
// that stops answering blocks the caller forever.
func Connect(dial as400.DialOptions, userID, password string, opts Options) (*Conn, error) {
	if dial.Port == 0 {
		if dial.TLSConfig != nil {
			dial.Port = as400.PortDatabaseSecure
		} else {
			dial.Port = as400.PortDatabasePlain
		}
	}
	if opts.Location == nil {
		opts.Location = time.UTC
	}
	if opts.BlockSize <= 0 {
		opts.BlockSize = defaultBlockSize
	}

	conn, err := as400.Dial(dial)
	if err != nil {
		return nil, err
	}
	if _, err := as400.Logon(conn, as400.ServerDatabase, userID, password); err != nil {
		conn.Close()
		return nil, err
	}
	c := &Conn{conn: conn, opts: opts}
	if err := c.setServerAttributes(); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// Close closes the connection, ending the server job. Uncommitted work is
// rolled back by the server.
func (c *Conn) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

// ServerCCSID, VRM and JobID report what the server returned when the
// connection was set up: the job's CCSID, the IBM i release as
// version<<16 | release<<8 | modification, and the qualified server job
// name (when the server's functional level supports returning it).
func (c *Conn) ServerCCSID() int { return c.serverCCSID }
func (c *Conn) VRM() int         { return c.vrm }
func (c *Conn) JobID() string    { return c.jobID }

// Ping checks that the server job is still answering, by retrieving its
// SQL attributes.
func (c *Conn) Ping(ctx context.Context) error {
	req := &request{functionID: fnRetrieveAttributes, ors: orsReply | orsServerAttributes}
	rep, err := c.call(ctx, req)
	if err != nil {
		return err
	}
	if rep.failed() {
		return newError("ping", rep)
	}
	return nil
}

// InTransaction reports whether Begin has started a transaction that has
// not yet been committed or rolled back.
func (c *Conn) InTransaction() bool { return c.inTx }

// Begin turns autocommit off and starts a transaction at the given
// isolation level, which Commit or Rollback ends (restoring autocommit).
func (c *Conn) Begin(ctx context.Context, level Isolation) error {
	if c.inTx {
		return errors.New("database: a transaction is already in progress")
	}
	if level < IsolationReadUncommitted || level > IsolationSerializable {
		return fmt.Errorf("database: unsupported isolation level %d for a transaction", level)
	}
	if err := c.setAutoCommit(ctx, false, level); err != nil {
		return err
	}
	c.inTx = true
	return nil
}

// Commit commits the current transaction and restores autocommit. If the
// commit fails, Commit rolls back instead and returns the commit error; if
// the connection's transaction state cannot be restored, the connection
// is marked broken so that a pool discards it rather than reusing a job
// with work still pending.
func (c *Conn) Commit(ctx context.Context) error {
	return c.endTransaction(ctx, fnCommit, "commit")
}

// Rollback rolls back the current transaction and restores autocommit.
func (c *Conn) Rollback(ctx context.Context) error {
	return c.endTransaction(ctx, fnRollback, "rollback")
}

func (c *Conn) endTransaction(ctx context.Context, functionID uint16, op string) error {
	if !c.inTx {
		return errors.New("database: no transaction in progress")
	}
	endErr := c.commitOrRollback(ctx, functionID, op)
	if endErr != nil && functionID == fnCommit {
		if rbErr := c.commitOrRollback(ctx, fnRollback, "rollback"); rbErr != nil {
			c.broken = true
			return errors.Join(endErr, rbErr)
		}
	}
	if err := c.setAutoCommit(ctx, true, IsolationNone); err != nil {
		c.broken = true
		return errors.Join(endErr, err)
	}
	c.inTx = false
	return endErr
}

func (c *Conn) commitOrRollback(ctx context.Context, functionID uint16, op string) error {
	req := &request{functionID: functionID, ors: orsReply | orsSQLCA}
	req.addByte(0x380F, 1) // hold indicator: keep cursors open, JTOpen's default
	rep, err := c.call(ctx, req)
	if err != nil {
		return err
	}
	if rep.failed() {
		return newError(op, rep)
	}
	return nil
}

// setAutoCommit mirrors JDTransactionManager.setAutoCommit for servers
// with "new auto commit support" (V5R3 and later): autocommit on runs with
// no commitment control; off runs at the requested level.
func (c *Conn) setAutoCommit(ctx context.Context, on bool, level Isolation) error {
	req := &request{functionID: fnSetAttributes, ors: orsReply | orsServerAttributes}
	if on {
		req.addByte(0x3824, 0xE8) // 'Y'
		req.addShort(0x380E, uint16(IsolationNone))
	} else {
		req.addByte(0x3824, 0xD5) // 'N'
		req.addShort(0x380E, uint16(level))
	}
	rep, err := c.call(ctx, req)
	if err != nil {
		return err
	}
	if rep.failed() {
		return newError("set autocommit", rep)
	}
	return nil
}

// setServerAttributes sends the connection's initial SET_ATTRIBUTES,
// following AS400JDBCConnectionImpl.setServerAttributes with JTOpen's
// default properties, minus the options this client does not support
// (sort sequences, packages, LOB locators, compression, client info).
func (c *Conn) setServerAttributes() error {
	req := &request{functionID: fnSetAttributes, ors: orsReply | orsServerAttributes}
	req.addShort(0x3801, clientCCSID)
	req.add(0x3802, zonedText(languageFeatureCode))
	level, err := auth.EncodeEBCDIC(clientFunctionalLevel)
	if err != nil {
		return err
	}
	// DBBaseRequestDS.addParameter(cp, converter, value, fixed=true)
	// reserves two bytes more than it fills; the server sees them as zeros.
	fixed := make([]byte, 2+len(level)+2)
	binary.BigEndian.PutUint16(fixed[0:2], ccsidEBCDIC37)
	copy(fixed[2:], level)
	req.add(0x3803, fixed)
	req.addByte(0x3805, 0xF0) // translate indicator
	req.addShort(0x3806, 1)   // DRDA package size
	req.addByte(0x3824, 0xE8) // autocommit on
	req.addShort(0x380E, 0)   // commitment control *NONE (autocommit)
	req.addShort(0x3807, 5)   // date format ISO
	req.addShort(0x3809, 2)   // time format ISO
	naming := uint16(0)       // SQL naming
	if c.opts.SystemNaming {
		naming = 1
	}
	req.addShort(0x380C, naming)
	req.addShort(0x3823, 0) // no data compression
	if c.opts.DefaultSchema != "" {
		schema, err := encodeString(ccsidEBCDIC37, c.opts.DefaultSchema)
		if err != nil {
			return err
		}
		req.addText(0x380F, ccsidEBCDIC37, schema)
	}
	req.addByte(0x3821, 0xF1) // extended data formats (V4R4+), not super-extended
	req.addInt(0x3822, 32768) // LOB field threshold: JTOpen's default
	req.addShort(0x3811, 1)   // ambiguous SELECTs are read-only

	rep, err := c.call(context.Background(), req)
	if err != nil {
		return fmt.Errorf("database: set server attributes: %w", err)
	}
	if rep.failed() {
		return newError("set server attributes", rep)
	}
	return c.parseServerAttributes(rep.serverAttributes)
}

// parseServerAttributes reads DBReplyServerAttributes: server CCSID at 19,
// functional level ("V7R4M0  10") at 50, job identifier at 88.
func (c *Conn) parseServerAttributes(a []byte) error {
	if len(a) < 60 {
		return fmt.Errorf("database: server attributes reply too short (%d bytes)", len(a))
	}
	c.serverCCSID = int(binary.BigEndian.Uint16(a[19:21]))
	c.vrm = int(a[51]&0x0F)<<16 | int(a[53]&0x0F)<<8 | int(a[55]&0x0F)
	level := decodeServerText(c.serverCCSID, a[50:60])
	if len(level) >= 10 {
		c.functionalLevel, _ = strconv.Atoi(strings.TrimSpace(level[6:]))
	}
	if c.functionalLevel >= 5 && len(a) >= 114 {
		// The 26-character job identifier is name(10) + user(10) +
		// number(6); render it in the usual number/user/name form.
		id := decodeServerText(c.serverCCSID, a[88:114])
		if len(id) == 26 {
			c.jobID = strings.TrimSpace(id[20:26]) + "/" + strings.TrimSpace(id[10:20]) + "/" + strings.TrimSpace(id[0:10])
		} else {
			c.jobID = strings.TrimSpace(id)
		}
	}
	return nil
}

// zonedText encodes a numeric string as CCSID-37-tagged EBCDIC digits:
// DBBaseRequestDS.addParameter(int, String).
func zonedText(s string) []byte {
	b := make([]byte, 2+len(s))
	binary.BigEndian.PutUint16(b[0:2], ccsidEBCDIC37)
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			b[2+i] = 0x40
		} else {
			b[2+i] = s[i] | 0xF0
		}
	}
	return b
}

// call sends a reply-producing request and decodes its reply. Any I/O or
// decoding failure marks the connection broken: the datastream can no
// longer be trusted to be in step with the server.
func (c *Conn) call(ctx context.Context, req *request) (*reply, error) {
	if err := c.usable(); err != nil {
		return nil, err
	}
	raw, err := c.conn.CallContext(ctx, req.encode())
	if err != nil {
		c.broken = true
		return nil, err
	}
	rep, err := parseReply(raw)
	if err != nil {
		c.broken = true
		return nil, err
	}
	return rep, nil
}

// send sends a request whose operation-result bitmap asks for no reply.
func (c *Conn) send(req *request) error {
	if err := c.usable(); err != nil {
		return err
	}
	if req.ors != 0 {
		return fmt.Errorf("database: internal error: request %#04x expects a reply but was sent without waiting for one", req.functionID)
	}
	if err := c.conn.Send(req.encode()); err != nil {
		c.broken = true
		return err
	}
	return nil
}

func (c *Conn) usable() error {
	switch {
	case c.closed:
		return ErrClosed
	case c.broken:
		return ErrConnBroken
	}
	return nil
}

func (c *Conn) allocID() (uint16, error) {
	for i := 1; i <= maxStatements; i++ {
		if !c.ids[i] {
			c.ids[i] = true
			return uint16(i), nil
		}
	}
	return 0, fmt.Errorf("database: more than %d open statements on one connection", maxStatements)
}

func (c *Conn) freeID(id uint16) { c.ids[id] = false }
