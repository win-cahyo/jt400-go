package database

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// Statement types (JDSQLStatement.TYPE_*), sent with every prepare and
// execute.
const (
	stmtTypeUndetermined = 0
	stmtTypeOther        = 1
	stmtTypeSelect       = 2
	stmtTypeCall         = 3
)

// Cursor close reuse indicators (JDCursor.REUSE_*).
const (
	reuseNo  = 0xF0
	reuseYes = 0xF1
)

// Stmt is a prepared SQL statement, backed by one request parameter block
// (RPB) in the server job. Close it to release the RPB.
type Stmt struct {
	c        *Conn
	id       uint16
	query    string
	stmtType uint16

	columns []field // nil unless the statement returns rows
	params  []field

	descriptorSent bool
	rows           *Rows
	closed         bool
}

// Result reports the outcome of Stmt.Exec.
type Result struct {
	// RowsAffected is SQLERRD(3) from the SQLCA: the number of rows
	// inserted, updated or deleted.
	RowsAffected int64
}

// Prepare prepares query, which may contain ? parameter markers, and
// describes its result columns and parameters.
func (c *Conn) Prepare(ctx context.Context, query string) (*Stmt, error) {
	if err := c.usable(); err != nil {
		return nil, err
	}
	id, err := c.allocID()
	if err != nil {
		return nil, err
	}
	st := &Stmt{c: c, id: id, query: query, stmtType: statementType(query)}

	// AS400JDBCStatement.syncRPB: create the RPB, naming the statement and
	// its cursor, without waiting for a reply.
	rpb := &request{functionID: fnCreateRPB, rpbID: id}
	if err := rpb.addName(0x3806, fmt.Sprintf("STMT%04d", id)); err != nil {
		c.freeID(id)
		return nil, err
	}
	if err := rpb.addName(0x380B, fmt.Sprintf("CRSR%04d", id)); err != nil {
		c.freeID(id)
		return nil, err
	}
	if err := c.send(rpb); err != nil {
		c.freeID(id)
		return nil, err
	}

	text, err := encodeString(clientCCSID, query)
	if err != nil {
		st.release(ctx)
		return nil, err
	}
	prep := &request{
		functionID: fnPrepareDescribe,
		rpbID:      id,
		ors:        orsReply | orsDataFormat | orsSQLCA | orsParameterMarkerFormat,
	}
	if c.vrm >= vrmV5R4 {
		prep.addLongText(0x3831, clientCCSID, text)
	} else {
		if len(text) > 0xFFFF {
			st.release(ctx)
			return nil, fmt.Errorf("database: statement text of %d bytes exceeds the %d-byte limit before V5R4", len(text), 0xFFFF)
		}
		prep.addText(0x3807, clientCCSID, text)
	}
	prep.addShort(0x3812, st.stmtType)
	prep.addByte(0x3808, 0) // prepare option: not packaged

	rep, err := c.call(ctx, prep)
	if err != nil {
		st.release(ctx)
		return nil, err
	}
	if rep.failed() {
		st.release(ctx)
		return nil, newError("prepare", rep)
	}
	if rep.dataFormat != nil && len(rep.dataFormat.fields) > 0 {
		st.columns = rep.dataFormat.fields
	}
	if rep.paramFormat != nil {
		st.params = rep.paramFormat.fields
	}
	return st, nil
}

// NumInput returns the number of ? parameter markers.
func (st *Stmt) NumInput() int { return len(st.params) }

// ReturnsRows reports whether the statement produces a result set, i.e.
// whether it must be run with Query rather than Exec.
func (st *Stmt) ReturnsRows() bool { return st.columns != nil }

// Exec runs a statement that does not return rows.
func (st *Stmt) Exec(ctx context.Context, args ...any) (Result, error) {
	values, err := convertArgs(args)
	if err != nil {
		return Result{}, err
	}
	return st.exec(ctx, values)
}

func (st *Stmt) exec(ctx context.Context, args []driver.Value) (Result, error) {
	if err := st.usable(); err != nil {
		return Result{}, err
	}
	if st.columns != nil {
		return Result{}, errors.New("database: statement returns rows; use Query")
	}
	if err := st.closeRows(reuseYes); err != nil {
		return Result{}, err
	}
	data, err := st.bind(args)
	if err != nil {
		return Result{}, err
	}
	req := &request{functionID: fnExecute, rpbID: st.id, ors: orsReply | orsSQLCA}
	st.addExecuteParams(req, data)
	rep, err := st.c.call(ctx, req)
	if err != nil {
		return Result{}, err
	}
	if rep.failed() {
		return Result{}, newError("execute", rep)
	}
	return Result{RowsAffected: rep.rowCount()}, nil
}

// Query runs a statement that returns rows and opens a forward-only,
// read-only cursor over them. Only one Rows per Stmt is open at a time:
// running the statement again closes the previous Rows.
func (st *Stmt) Query(ctx context.Context, args ...any) (*Rows, error) {
	values, err := convertArgs(args)
	if err != nil {
		return nil, err
	}
	return st.queryValues(ctx, values)
}

func (st *Stmt) queryValues(ctx context.Context, args []driver.Value) (*Rows, error) {
	if err := st.usable(); err != nil {
		return nil, err
	}
	if st.columns == nil {
		return nil, errors.New("database: statement does not return rows; use Exec")
	}
	if err := st.closeRows(reuseYes); err != nil {
		return nil, err
	}
	data, err := st.bind(args)
	if err != nil {
		return nil, err
	}
	// AS400JDBCStatement.commonExecute with prefetch: open the cursor and
	// fetch the first block in one round trip.
	req := &request{functionID: fnOpenDescribeFetch, rpbID: st.id, ors: orsReply | orsSQLCA | orsResultData}
	req.addByte(0x3809, 0x80) // open attributes: read-only
	req.addInt(0x380C, st.blockingFactor())
	req.addShort(0x380D, 0) // scrollable cursor flag: not scrollable, asensitive
	st.addExecuteParams(req, data)
	rep, err := st.c.call(ctx, req)
	if err != nil {
		return nil, err
	}
	if rep.failed() {
		return nil, newError("open cursor", rep)
	}
	r := &Rows{st: st, block: rep.resultData, cursorOpen: true}
	r.absorbEnd(rep)
	st.rows = r
	return r, nil
}

func (st *Stmt) addExecuteParams(req *request, data []byte) {
	req.addShort(0x3812, st.stmtType)
	if len(st.params) > 0 {
		req.pmHandle = st.id
		req.add(0x381F, data)
	}
}

// bind encodes args against the described parameter markers and, the
// first time, sends the parameter-marker descriptor (CHANGE_DESCRIPTOR)
// that tells the server how the data is laid out.
func (st *Stmt) bind(args []driver.Value) ([]byte, error) {
	if len(args) != len(st.params) {
		return nil, fmt.Errorf("database: statement has %d parameter markers but %d arguments were given", len(st.params), len(args))
	}
	if len(st.params) == 0 {
		return nil, nil
	}
	values := make([][]byte, len(args))
	for i, a := range args {
		if a == nil {
			continue
		}
		b, err := encodeValue(st.params[i], a, st.c.opts.Location)
		if err != nil {
			return nil, fmt.Errorf("database: parameter %d: %w", i+1, err)
		}
		values[i] = b
	}
	if !st.descriptorSent {
		req := &request{functionID: fnChangeDescriptor, rpbID: st.id, pmHandle: st.id}
		req.add(0x381E, encodeParameterFormat(st.params))
		if err := st.c.send(req); err != nil {
			return nil, err
		}
		st.descriptorSent = true
	}
	return encodeParameterData(st.params, values), nil
}

// blockingFactor mirrors AS400JDBCStatement.getBlockingFactor: as many
// rows as fit the block size, between 1 and 32767.
func (st *Stmt) blockingFactor() uint32 {
	rowLen := recordSize(st.columns)
	if rowLen <= 0 {
		return 1
	}
	n := st.c.opts.BlockSize / rowLen
	switch {
	case n < 1:
		n = 1
	case n > 32767:
		n = 32767
	}
	return uint32(n)
}

func (st *Stmt) closeRows(reuse byte) error {
	if st.rows == nil {
		return nil
	}
	return st.rows.close(reuse)
}

// Close closes any open cursor and releases the statement's descriptor
// and RPB in the server job.
func (st *Stmt) Close() error {
	if st.closed {
		return nil
	}
	return st.release(context.Background())
}

func (st *Stmt) release(ctx context.Context) error {
	st.closed = true
	defer st.c.freeID(st.id)
	if st.c.usable() != nil {
		return nil // the server job's resources go with the connection
	}
	var errs []error
	if err := st.closeRows(reuseNo); err != nil {
		errs = append(errs, err)
	}
	if st.descriptorSent {
		req := &request{functionID: fnDeleteDescriptor, rpbID: st.id, pmHandle: st.id}
		if err := st.c.send(req); err != nil {
			return errors.Join(append(errs, err)...)
		}
	}
	rep, err := st.c.call(ctx, &request{functionID: fnDeleteRPB, rpbID: st.id, ors: orsReply})
	if err != nil {
		errs = append(errs, err)
	} else if rep.failed() {
		errs = append(errs, newError("close statement", rep))
	}
	return errors.Join(errs...)
}

func (st *Stmt) usable() error {
	if st.closed {
		return ErrClosed
	}
	return st.c.usable()
}

// Rows is an open cursor over a statement's result set.
type Rows struct {
	st    *Stmt
	block *resultData
	next  int

	eof        bool // the server has no rows beyond the current block
	cursorOpen bool // the server-side cursor still needs closing
	closed     bool
	closeStmt  bool // Conn.Query made the Stmt just for this Rows
}

// Columns returns the result column names.
func (r *Rows) Columns() []string {
	names := make([]string, len(r.st.columns))
	for i, f := range r.st.columns {
		names[i] = f.name
	}
	return names
}

// ColumnTypes describes each result column: database type name (e.g.
// "DECIMAL"), nullability, length in bytes, and precision/scale.
func (r *Rows) ColumnTypes() []ColumnType {
	types := make([]ColumnType, len(r.st.columns))
	for i, f := range r.st.columns {
		types[i] = ColumnType{
			Name:      f.name,
			TypeName:  typeName(f.baseType()),
			Nullable:  f.nullable(),
			Length:    f.length,
			Precision: f.precision,
			Scale:     f.scale,
			CCSID:     f.ccsid,
		}
	}
	return types
}

// ColumnType describes one result column.
type ColumnType struct {
	Name      string
	TypeName  string
	Nullable  bool
	Length    int
	Precision int
	Scale     int
	CCSID     int
}

// Next decodes the next row into dest (one element per column), fetching
// another block from the server when the current one is exhausted. It
// returns io.EOF after the last row.
func (r *Rows) Next(dest []driver.Value) error {
	if r.closed {
		return ErrClosed
	}
	for r.block == nil || r.next >= r.block.rowCount {
		if r.eof {
			return io.EOF
		}
		if err := r.fetch(); err != nil {
			return err
		}
	}
	if len(dest) != len(r.st.columns) {
		return fmt.Errorf("database: row has %d columns, destination has %d", len(r.st.columns), len(dest))
	}
	if r.block.columnCount != len(r.st.columns) {
		return fmt.Errorf("database: result data has %d columns, statement describes %d", r.block.columnCount, len(r.st.columns))
	}
	row := r.block.row(r.next)
	off := 0
	for i, f := range r.st.columns {
		if off+f.length > len(row) {
			return fmt.Errorf("database: row of %d bytes too short for column %d", len(row), i+1)
		}
		switch ind := r.block.indicator(r.next, i); {
		case ind == -1:
			dest[i] = nil
		case ind < 0:
			return fmt.Errorf("database: column %d (%s): data mapping error (indicator %d)", i+1, f.name, ind)
		default:
			v, err := decodeValue(f, row[off:off+f.length], r.st.c.opts.Location)
			if err != nil {
				return fmt.Errorf("database: column %d (%s): %w", i+1, f.name, err)
			}
			dest[i] = v
		}
		off += f.length
	}
	r.next++
	return nil
}

func (r *Rows) fetch() error {
	req := &request{functionID: fnFetch, rpbID: r.st.id, ors: orsReply | orsResultData}
	req.addShort(0x380E, 0) // fetch scroll option: next
	req.addInt(0x380C, r.st.blockingFactor())
	rep, err := r.st.c.call(context.Background(), req)
	if err != nil {
		return err
	}
	if rep.failed() {
		return newError("fetch", rep)
	}
	r.block, r.next = rep.resultData, 0
	r.absorbEnd(rep)
	if !r.eof && (r.block == nil || r.block.rowCount == 0) {
		// A non-final block with no rows would loop forever; treat it as
		// the end, as JDServerRowCache does when no result data comes back.
		r.eof = true
	}
	return nil
}

func (r *Rows) absorbEnd(rep *reply) {
	if rep.endOfData() {
		r.eof = true
	}
	if rep.cursorClosedByServer() {
		r.cursorOpen = false
	}
}

// Close closes the cursor. It does not close the statement, which can be
// run again — unless the Rows came from Conn.Query, whose one-off
// statement is closed along with it.
func (r *Rows) Close() error {
	if r.closed {
		return nil
	}
	err := r.close(reuseYes)
	if r.closeStmt {
		err = errors.Join(err, r.st.Close())
	}
	return err
}

func (r *Rows) close(reuse byte) error {
	r.closed = true
	if r.st.rows == r {
		r.st.rows = nil
	}
	if !r.cursorOpen || r.st.c.usable() != nil {
		return nil
	}
	r.cursorOpen = false
	req := &request{functionID: fnClose, rpbID: r.st.id}
	req.addByte(0x3810, reuse)
	return r.st.c.send(req)
}

// Exec prepares, runs and closes a statement that does not return rows.
func (c *Conn) Exec(ctx context.Context, query string, args ...any) (Result, error) {
	st, err := c.Prepare(ctx, query)
	if err != nil {
		return Result{}, err
	}
	res, err := st.Exec(ctx, args...)
	return res, errors.Join(err, st.Close())
}

// Query prepares and runs a statement that returns rows. Closing the Rows
// also closes the statement.
func (c *Conn) Query(ctx context.Context, query string, args ...any) (*Rows, error) {
	st, err := c.Prepare(ctx, query)
	if err != nil {
		return nil, err
	}
	rows, err := st.Query(ctx, args...)
	if err != nil {
		return nil, errors.Join(err, st.Close())
	}
	rows.closeStmt = true
	return rows, nil
}

// statementType classifies query by its first keyword the way
// JDSQLStatement does, as far as the server needs to know.
func statementType(query string) uint16 {
	switch firstKeyword(query) {
	case "SELECT", "WITH", "VALUES":
		return stmtTypeSelect
	case "CALL":
		return stmtTypeCall
	case "SET":
		return stmtTypeUndetermined
	default:
		return stmtTypeOther
	}
}

// firstKeyword returns the first word of query, upper-cased, skipping
// leading whitespace, opening parentheses and SQL comments.
func firstKeyword(query string) string {
	s := query
	for {
		s = strings.TrimLeftFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r == '(' })
		switch {
		case strings.HasPrefix(s, "--"):
			if i := strings.IndexByte(s, '\n'); i >= 0 {
				s = s[i+1:]
				continue
			}
			return ""
		case strings.HasPrefix(s, "/*"):
			if i := strings.Index(s, "*/"); i >= 0 {
				s = s[i+2:]
				continue
			}
			return ""
		}
		break
	}
	end := strings.IndexFunc(s, func(r rune) bool { return !unicode.IsLetter(r) })
	if end < 0 {
		end = len(s)
	}
	return strings.ToUpper(s[:end])
}

// convertArgs normalizes Go arguments to driver.Values the way
// database/sql does (int → int64, driver.Valuer, pointers, and so on).
func convertArgs(args []any) ([]driver.Value, error) {
	values := make([]driver.Value, len(args))
	for i, a := range args {
		v, err := driver.DefaultParameterConverter.ConvertValue(a)
		if err != nil {
			return nil, fmt.Errorf("database: parameter %d: %w", i+1, err)
		}
		values[i] = v
	}
	return values, nil
}
