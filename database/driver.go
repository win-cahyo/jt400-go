package database

import (
	"context"
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/win-cahyo/jt400-go/as400"
)

// DriverName is the name this package registers with database/sql.
const DriverName = "jt400"

func init() {
	sql.Register(DriverName, &Driver{})
}

// Driver is the database/sql driver. Open takes a DSN of the form
//
//	jt400://USER:PASSWORD@HOST[:PORT]?param=value&...
//
// with optional parameters:
//
//	tls=true            connect to the SSL port (9471) with default TLS settings
//	naming=system       system naming (LIB/FILE) instead of SQL naming
//	schema=LIB          default schema for unqualified names
//	timeout=10s         dial timeout
//	iotimeout=90s       per-request timeout (strongly recommended)
//	location=Asia/Jakarta   time zone for DATE/TIMESTAMP values (default UTC)
//	blocksize=32768     bytes per fetched block of rows
//
// Special characters in the user or password must be percent-encoded. Use
// NewConnector with sql.OpenDB instead to pass a custom tls.Config (for
// example, an internal CA) or to keep the password out of a string.
type Driver struct{}

// Open opens a new connection described by dsn.
func (d *Driver) Open(dsn string) (driver.Conn, error) {
	c, err := d.OpenConnector(dsn)
	if err != nil {
		return nil, err
	}
	return c.Connect(context.Background())
}

// OpenConnector parses dsn once, for sql.DB to reuse for every connection.
func (d *Driver) OpenConnector(dsn string) (driver.Connector, error) {
	return ParseDSN(dsn)
}

// Connector holds everything needed to open a connection, for use with
// sql.OpenDB.
type Connector struct {
	Dial     as400.DialOptions
	UserID   string
	Password string
	Options  Options
}

// NewConnector returns a Connector for sql.OpenDB.
func NewConnector(dial as400.DialOptions, userID, password string, opts Options) *Connector {
	return &Connector{Dial: dial, UserID: userID, Password: password, Options: opts}
}

// Connect opens one connection. The dial timeout in Dial.Timeout bounds
// the TCP/TLS dial; the logon handshake that follows is bounded by
// Dial.IOTimeout.
func (c *Connector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := Connect(c.Dial, c.UserID, c.Password, c.Options)
	if err != nil {
		return nil, err
	}
	return &driverConn{c: conn}, nil
}

// Driver returns the package's Driver.
func (c *Connector) Driver() driver.Driver { return &Driver{} }

// ParseDSN parses a jt400:// DSN (see Driver) into a Connector.
func ParseDSN(dsn string) (*Connector, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("database: parse DSN: %w", err)
	}
	if u.Scheme != DriverName {
		return nil, fmt.Errorf("database: DSN scheme must be %q, got %q", DriverName, u.Scheme)
	}
	if u.Hostname() == "" || u.User == nil || u.User.Username() == "" {
		return nil, errors.New("database: DSN must name a user and host: jt400://USER:PASSWORD@HOST")
	}
	c := &Connector{UserID: u.User.Username()}
	c.Password, _ = u.User.Password()
	c.Dial.Host = u.Hostname()
	if p := u.Port(); p != "" {
		if c.Dial.Port, err = strconv.Atoi(p); err != nil {
			return nil, fmt.Errorf("database: DSN port %q: %w", p, err)
		}
	}

	q := u.Query()
	for key, vals := range q {
		v := vals[len(vals)-1]
		switch key {
		case "tls":
			on, err := strconv.ParseBool(v)
			if err != nil {
				return nil, fmt.Errorf("database: DSN tls=%q: %w", v, err)
			}
			if on {
				c.Dial.TLSConfig = &tls.Config{ServerName: c.Dial.Host}
			}
		case "naming":
			switch v {
			case "sql":
			case "system":
				c.Options.SystemNaming = true
			default:
				return nil, fmt.Errorf("database: DSN naming=%q: want sql or system", v)
			}
		case "schema":
			c.Options.DefaultSchema = v
		case "timeout":
			if c.Dial.Timeout, err = time.ParseDuration(v); err != nil {
				return nil, fmt.Errorf("database: DSN timeout=%q: %w", v, err)
			}
		case "iotimeout":
			if c.Dial.IOTimeout, err = time.ParseDuration(v); err != nil {
				return nil, fmt.Errorf("database: DSN iotimeout=%q: %w", v, err)
			}
		case "location":
			if c.Options.Location, err = time.LoadLocation(v); err != nil {
				return nil, fmt.Errorf("database: DSN location=%q: %w", v, err)
			}
		case "blocksize":
			if c.Options.BlockSize, err = strconv.Atoi(v); err != nil {
				return nil, fmt.Errorf("database: DSN blocksize=%q: %w", v, err)
			}
		default:
			return nil, fmt.Errorf("database: unknown DSN parameter %q", key)
		}
	}
	return c, nil
}

// driverConn adapts Conn to database/sql/driver.
type driverConn struct {
	c *Conn
}

var (
	_ driver.Conn               = (*driverConn)(nil)
	_ driver.ConnPrepareContext = (*driverConn)(nil)
	_ driver.ConnBeginTx        = (*driverConn)(nil)
	_ driver.Pinger             = (*driverConn)(nil)
	_ driver.SessionResetter    = (*driverConn)(nil)
	_ driver.Validator          = (*driverConn)(nil)
)

// badConn maps ErrConnBroken — returned only before anything was sent —
// to driver.ErrBadConn, so that database/sql retries on a fresh
// connection. Errors from a request that may have reached the server are
// never mapped: retrying them could run a statement twice.
func badConn(err error) error {
	if errors.Is(err, ErrConnBroken) {
		return driver.ErrBadConn
	}
	return err
}

func (d *driverConn) Prepare(query string) (driver.Stmt, error) {
	return d.PrepareContext(context.Background(), query)
}

func (d *driverConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	st, err := d.c.Prepare(ctx, query)
	if err != nil {
		return nil, badConn(err)
	}
	return &driverStmt{s: st}, nil
}

func (d *driverConn) Close() error { return d.c.Close() }

func (d *driverConn) Begin() (driver.Tx, error) {
	return d.BeginTx(context.Background(), driver.TxOptions{})
}

func (d *driverConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if opts.ReadOnly {
		return nil, errors.New("database: read-only transactions are not supported")
	}
	var level Isolation
	switch sql.IsolationLevel(opts.Isolation) {
	case sql.LevelDefault, sql.LevelReadUncommitted:
		level = IsolationReadUncommitted // JTOpen's default (*CHG)
	case sql.LevelReadCommitted:
		level = IsolationReadCommitted
	case sql.LevelRepeatableRead:
		level = IsolationRepeatableRead
	case sql.LevelSerializable:
		level = IsolationSerializable
	default:
		return nil, fmt.Errorf("database: isolation level %v is not supported", sql.IsolationLevel(opts.Isolation))
	}
	if err := d.c.Begin(ctx, level); err != nil {
		return nil, badConn(err)
	}
	return &driverTx{c: d.c}, nil
}

func (d *driverConn) Ping(ctx context.Context) error { return badConn(d.c.Ping(ctx)) }

func (d *driverConn) ResetSession(ctx context.Context) error {
	if d.c.broken || d.c.closed || d.c.inTx {
		return driver.ErrBadConn
	}
	return nil
}

func (d *driverConn) IsValid() bool { return !d.c.broken && !d.c.closed && !d.c.inTx }

type driverTx struct{ c *Conn }

func (t *driverTx) Commit() error   { return t.c.Commit(context.Background()) }
func (t *driverTx) Rollback() error { return t.c.Rollback(context.Background()) }

type driverStmt struct{ s *Stmt }

var (
	_ driver.StmtExecContext  = (*driverStmt)(nil)
	_ driver.StmtQueryContext = (*driverStmt)(nil)
)

func (s *driverStmt) Close() error  { return s.s.Close() }
func (s *driverStmt) NumInput() int { return s.s.NumInput() }

func (s *driverStmt) Exec(args []driver.Value) (driver.Result, error) {
	res, err := s.s.exec(context.Background(), args)
	if err != nil {
		return nil, badConn(err)
	}
	return newDriverResult(res), nil
}

func (s *driverStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	values, err := positional(args)
	if err != nil {
		return nil, err
	}
	res, err := s.s.exec(ctx, values)
	if err != nil {
		return nil, badConn(err)
	}
	return newDriverResult(res), nil
}

func (s *driverStmt) Query(args []driver.Value) (driver.Rows, error) {
	r, err := s.s.queryValues(context.Background(), args)
	if err != nil {
		return nil, badConn(err)
	}
	return &driverRows{r: r}, nil
}

func (s *driverStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	values, err := positional(args)
	if err != nil {
		return nil, err
	}
	r, err := s.s.queryValues(ctx, values)
	if err != nil {
		return nil, badConn(err)
	}
	return &driverRows{r: r}, nil
}

func positional(args []driver.NamedValue) ([]driver.Value, error) {
	values := make([]driver.Value, len(args))
	for i, a := range args {
		if a.Name != "" {
			return nil, errors.New("database: named parameters are not supported; use ? markers")
		}
		values[i] = a.Value
	}
	return values, nil
}

type driverResult struct{ rowsAffected int64 }

func newDriverResult(r Result) driverResult { return driverResult{rowsAffected: r.RowsAffected} }

func (r driverResult) LastInsertId() (int64, error) {
	return 0, errors.New("database: LastInsertId is not supported; use SELECT ... FROM FINAL TABLE (INSERT ...)")
}

func (r driverResult) RowsAffected() (int64, error) { return r.rowsAffected, nil }

type driverRows struct{ r *Rows }

var (
	_ driver.RowsColumnTypeDatabaseTypeName = (*driverRows)(nil)
	_ driver.RowsColumnTypeNullable         = (*driverRows)(nil)
	_ driver.RowsColumnTypePrecisionScale   = (*driverRows)(nil)
)

func (r *driverRows) Columns() []string              { return r.r.Columns() }
func (r *driverRows) Close() error                   { return r.r.Close() }
func (r *driverRows) Next(dest []driver.Value) error { return r.r.Next(dest) }

func (r *driverRows) ColumnTypeDatabaseTypeName(i int) string {
	return typeName(r.r.st.columns[i].baseType())
}

func (r *driverRows) ColumnTypeNullable(i int) (nullable, ok bool) {
	return r.r.st.columns[i].nullable(), true
}

func (r *driverRows) ColumnTypePrecisionScale(i int) (precision, scale int64, ok bool) {
	f := r.r.st.columns[i]
	switch f.baseType() {
	case typePacked, typeZoned:
		return int64(f.precision), int64(f.scale), true
	}
	return 0, 0, false
}
