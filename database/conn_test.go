package database

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/win-cahyo/jt400-go/as400"
)

// handlers maps function IDs to replies; unknown function IDs get an
// empty success reply (if they ask for one at all).
type handlers map[uint16]func(req *fakeRequest) *fakeReply

func (h handlers) with(t *testing.T) func(req *fakeRequest) *fakeReply {
	return func(req *fakeRequest) *fakeReply {
		if req.functionID == fnSetAttributes || req.functionID == fnRetrieveAttributes {
			if f, ok := h[req.functionID]; ok {
				return f(req)
			}
			return &fakeReply{params: []as400.Param{serverAttributesParam(t)}}
		}
		if f, ok := h[req.functionID]; ok {
			return f(req)
		}
		return nil
	}
}

func connect(t *testing.T, s *fakeServer, opts Options) *Conn {
	t.Helper()
	c, err := Connect(s.dial(), "TESTUSER", "secret", opts)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func u16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }

func TestConnectSetsServerAttributes(t *testing.T) {
	s := newFakeServer(t, handlers{}.with(t))
	c := connect(t, s, Options{DefaultSchema: "QGPL", SystemNaming: true})

	req := s.last(fnSetAttributes)
	if req == nil {
		t.Fatal("no SET_ATTRIBUTES request")
	}
	if req.rpbID != 0 {
		t.Errorf("attributes RPB handle = %d, want 0", req.rpbID)
	}
	checks := []struct {
		cp   uint16
		want []byte
	}{
		{0x3801, []byte{0x34, 0xB0}},                    // client CCSID 13488
		{0x3802, []byte{0, 37, 0xF2, 0xF9, 0xF2, 0xF4}}, // NLV "2924"
		{0x3807, []byte{0, 5}},                          // date format ISO
		{0x3809, []byte{0, 2}},                          // time format ISO
		{0x380C, []byte{0, 1}},                          // system naming
		{0x380E, []byte{0, 0}},                          // commitment control *NONE
		{0x3821, []byte{0xF1}},                          // extended formats
		{0x3824, []byte{0xE8}},                          // autocommit on
	}
	for _, ck := range checks {
		if got := req.param(ck.cp); !bytes.Equal(got, ck.want) {
			t.Errorf("param %#04x = % x, want % x", ck.cp, got, ck.want)
		}
	}
	schema := req.param(0x380F)
	if len(schema) < 4 || u16(schema[0:2]) != 37 || !bytes.Equal(schema[4:], ebcdic(t, "QGPL")) {
		t.Errorf("default schema param = % x", schema)
	}
	level := req.param(0x3803)
	if len(level) != 14 || !bytes.Equal(level[2:12], ebcdic(t, clientFunctionalLevel)) {
		t.Errorf("client functional level param = % x", level)
	}

	if c.ServerCCSID() != 37 {
		t.Errorf("ServerCCSID = %d, want 37", c.ServerCCSID())
	}
	if c.VRM() != 7<<16|4<<8 {
		t.Errorf("VRM = %#x, want 0x070400", c.VRM())
	}
	if c.JobID() != "123456/QUSER/QZDASOINIT" {
		t.Errorf("JobID = %q", c.JobID())
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Errorf("Ping: %v", err)
	}
}

// bulkInsertFields mirrors the shape of an insert into QGPL.CMSBULK:
// TRX_ID CHAR(17), TR_AMT DECIMAL(15,0), TR_DESC VARCHAR(30) nullable.
var bulkInsertFields = []field{
	{sqlType: typeChar, length: 17, ccsid: 37},
	{sqlType: typePacked, length: 8, precision: 15},
	{sqlType: typeVarchar | 1, length: 32, ccsid: 37},
}

func TestExecWithParameters(t *testing.T) {
	const query = "INSERT INTO QGPL.CMSBULK (TRX_ID, TR_AMT, TR_DESC) VALUES (?, ?, ?)"
	s := newFakeServer(t, handlers{
		fnPrepareDescribe: func(req *fakeRequest) *fakeReply {
			return &fakeReply{params: []as400.Param{formatParam(t, cpExtendedParmFormat, bulkInsertFields), sqlcaParam(0, "", t)}}
		},
		fnExecute: func(req *fakeRequest) *fakeReply {
			return &fakeReply{params: []as400.Param{sqlcaParam(1, "00000", t)}}
		},
	}.with(t))
	c := connect(t, s, Options{})

	res, err := c.Exec(context.Background(), query, "TRX00000000000001", 1500000, nil)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if res.RowsAffected != 1 {
		t.Errorf("RowsAffected = %d, want 1", res.RowsAffected)
	}

	want := []uint16{fnSetAttributes, fnCreateRPB, fnPrepareDescribe, fnChangeDescriptor, fnExecute, fnDeleteDescriptor, fnDeleteRPB}
	if got := s.functionIDs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("request sequence = %#04x, want %#04x", got, want)
	}

	rpb := s.last(fnCreateRPB)
	if rpb.ors != 0 || rpb.rpbID != 1 {
		t.Errorf("CREATE_RPB ors=%#x rpb=%d, want no reply on RPB 1", rpb.ors, rpb.rpbID)
	}
	if name := rpb.param(0x3806); !bytes.Equal(name[4:], ebcdic(t, "STMT0001")) {
		t.Errorf("statement name = % x", name)
	}

	prep := s.last(fnPrepareDescribe)
	text := prep.param(0x3831)
	if u16(text[0:2]) != clientCCSID {
		t.Errorf("statement text CCSID = %d, want %d", u16(text[0:2]), clientCCSID)
	}
	if got, _ := decodeString(clientCCSID, text[6:]); got != query {
		t.Errorf("statement text = %q", got)
	}
	if got := u16(prep.param(0x3812)); got != stmtTypeOther {
		t.Errorf("statement type = %d, want %d", got, stmtTypeOther)
	}

	desc := s.last(fnChangeDescriptor)
	if desc.ors != 0 || desc.pmHandle != 1 {
		t.Errorf("CHANGE_DESCRIPTOR ors=%#x pm=%d", desc.ors, desc.pmHandle)
	}
	df, err := parseDataFormat(desc.param(0x381E))
	if err != nil {
		t.Fatal(err)
	}
	if len(df.fields) != 3 || df.recordSize != 17+8+32 || df.fields[1].sqlType != typePacked|1 || df.fields[1].precision != 15 {
		t.Errorf("descriptor = %+v", df)
	}

	exec := s.last(fnExecute)
	if exec.pmHandle != 1 {
		t.Errorf("execute parameter-marker handle = %d, want 1", exec.pmHandle)
	}
	data, err := parseResultData(exec.param(0x381F))
	if err != nil {
		t.Fatal(err)
	}
	if data.rowCount != 1 || data.columnCount != 3 || data.indicator(0, 2) != -1 || data.indicator(0, 0) != 0 {
		t.Errorf("parameter data header/indicators wrong: %+v", data)
	}
	row := data.row(0)
	if !bytes.Equal(row[0:17], ebcdic(t, "TRX00000000000001")) {
		t.Errorf("TRX_ID bytes = % x", row[0:17])
	}
	if want := []byte{0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x0F}; !bytes.Equal(row[17:25], want) {
		t.Errorf("TR_AMT packed bytes = % x, want % x", row[17:25], want)
	}
}

// selectFields: ID CHAR(5), NAME VARCHAR(10), AMT DECIMAL(7,2), DT DATE,
// QTY INTEGER nullable.
var selectFields = []field{
	{sqlType: typeChar, length: 5, ccsid: 37, name: "ID"},
	{sqlType: typeVarchar, length: 12, ccsid: 37, name: "NAME"},
	{sqlType: typePacked, length: 4, precision: 7, scale: 2, name: "AMT"},
	{sqlType: typeDate, length: 10, ccsid: 37, name: "DT"},
	{sqlType: typeInteger | 1, length: 4, name: "QTY"},
}

func selectRow(t *testing.T, id, name, amt string, qty *int64) [][]byte {
	enc := func(i int, v driver.Value) []byte {
		b, err := encodeValue(selectFields[i], v, time.UTC)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	row := [][]byte{enc(0, id), enc(1, name), enc(2, amt), enc(3, "2026-10-13"), nil}
	if qty != nil {
		row[4] = enc(4, *qty)
	}
	return row
}

func selectServer(t *testing.T) *fakeServer {
	seven := int64(7)
	return newFakeServer(t, handlers{
		fnPrepareDescribe: func(req *fakeRequest) *fakeReply {
			return &fakeReply{params: []as400.Param{
				formatParam(t, cpExtendedFormat, selectFields),
				formatParam(t, cpExtendedParmFormat, []field{{sqlType: typeChar, length: 5, ccsid: 37}}),
			}}
		},
		fnOpenDescribeFetch: func(req *fakeRequest) *fakeReply {
			return &fakeReply{params: []as400.Param{rowsParam(selectFields, [][][]byte{
				selectRow(t, "A1", "alpha", "12.50", &seven),
				selectRow(t, "A2", "beta", "-0.75", nil),
			})}}
		},
		fnFetch: func(req *fakeRequest) *fakeReply {
			return &fakeReply{errorClass: errorClassHostServer, returnCode: 701, params: []as400.Param{
				rowsParam(selectFields, [][][]byte{selectRow(t, "A3", "gamma", "100", nil)}),
			}}
		},
	}.with(t))
}

func TestQueryFetchesUntilEndOfData(t *testing.T) {
	s := selectServer(t)
	c := connect(t, s, Options{})

	rows, err := c.Query(context.Background(), "SELECT ID, NAME, AMT, DT, QTY FROM T WHERE ID > ?", "A0")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if got := rows.Columns(); !reflect.DeepEqual(got, []string{"ID", "NAME", "AMT", "DT", "QTY"}) {
		t.Errorf("Columns = %v", got)
	}
	var got [][]driver.Value
	for {
		dest := make([]driver.Value, 5)
		err := rows.Next(dest)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		got = append(got, dest)
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	date := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	want := [][]driver.Value{
		{"A1   ", "alpha", "12.50", date, int64(7)},
		{"A2   ", "beta", "-0.75", date, nil},
		{"A3   ", "gamma", "100.00", date, nil},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rows =\n%v\nwant\n%v", got, want)
	}

	open := s.last(fnOpenDescribeFetch)
	if got := open.param(0x3809); !bytes.Equal(got, []byte{0x80}) {
		t.Errorf("open attributes = % x, want 80 (read-only)", got)
	}
	if bf := binary.BigEndian.Uint32(open.param(0x380C)); bf != uint32(defaultBlockSize/recordSize(selectFields)) {
		t.Errorf("blocking factor = %d", bf)
	}
	wantSeq := []uint16{fnSetAttributes, fnCreateRPB, fnPrepareDescribe, fnChangeDescriptor, fnOpenDescribeFetch, fnFetch, fnClose, fnDeleteDescriptor, fnDeleteRPB}
	if got := s.functionIDs(); !reflect.DeepEqual(got, wantSeq) {
		t.Errorf("request sequence = %#04x, want %#04x", got, wantSeq)
	}
	if cl := s.last(fnClose); cl.ors != 0 || !bytes.Equal(cl.param(0x3810), []byte{reuseYes}) {
		t.Errorf("CLOSE ors=%#x reuse=% x", cl.ors, cl.param(0x3810))
	}
}

func TestCursorClosedByServerIsNotClosedAgain(t *testing.T) {
	s := newFakeServer(t, handlers{
		fnPrepareDescribe: func(req *fakeRequest) *fakeReply {
			return &fakeReply{params: []as400.Param{formatParam(t, cpExtendedFormat, selectFields[:1])}}
		},
		fnOpenDescribeFetch: func(req *fakeRequest) *fakeReply {
			return &fakeReply{errorClass: errorClassHostServer, returnCode: 700}
		},
	}.with(t))
	c := connect(t, s, Options{})
	rows, err := c.Query(context.Background(), "SELECT ID FROM T")
	if err != nil {
		t.Fatal(err)
	}
	if err := rows.Next(make([]driver.Value, 1)); err != io.EOF {
		t.Fatalf("Next = %v, want io.EOF", err)
	}
	rows.Close()
	for _, id := range s.functionIDs() {
		if id == fnClose || id == fnFetch {
			t.Errorf("unexpected request %#04x after the server closed the cursor", id)
		}
	}
}

func TestSQLErrorCarriesServerMessage(t *testing.T) {
	s := newFakeServer(t, handlers{
		fnPrepareDescribe: func(req *fakeRequest) *fakeReply {
			params := append(messageParams(t, "SQL0204", "CMSBULKX in QGPL type *FILE not found."), sqlcaParam(0, "42704", t))
			return &fakeReply{errorClass: errorClassSQL, returnCode: -204, params: params}
		},
	}.with(t))
	c := connect(t, s, Options{})

	_, err := c.Exec(context.Background(), "DELETE FROM QGPL.CMSBULKX")
	var dbErr *Error
	if !errors.As(err, &dbErr) {
		t.Fatalf("Exec error = %v, want *Error", err)
	}
	if dbErr.SQLCode() != -204 || dbErr.SQLState != "42704" || dbErr.MessageID != "SQL0204" {
		t.Errorf("error fields = %+v", dbErr)
	}
	if !strings.Contains(dbErr.Error(), "*FILE not found") {
		t.Errorf("Error() = %q", dbErr.Error())
	}
	if s.last(fnDeleteRPB) == nil {
		t.Error("RPB of the failed prepare was not deleted")
	}
	if c.ids[1] {
		t.Error("statement ID of the failed prepare was not freed")
	}
}

func TestTransactionCommit(t *testing.T) {
	s := newFakeServer(t, handlers{}.with(t))
	c := connect(t, s, Options{})
	ctx := context.Background()

	if err := c.Begin(ctx, IsolationReadCommitted); err != nil {
		t.Fatal(err)
	}
	begin := s.last(fnSetAttributes)
	if !bytes.Equal(begin.param(0x3824), []byte{0xD5}) || !bytes.Equal(begin.param(0x380E), []byte{0, 2}) {
		t.Errorf("begin attributes: autocommit % x level % x", begin.param(0x3824), begin.param(0x380E))
	}
	if err := c.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	end := s.last(fnSetAttributes)
	if !bytes.Equal(end.param(0x3824), []byte{0xE8}) || !bytes.Equal(end.param(0x380E), []byte{0, 0}) {
		t.Errorf("restore attributes: autocommit % x level % x", end.param(0x3824), end.param(0x380E))
	}
	want := []uint16{fnSetAttributes, fnSetAttributes, fnCommit, fnSetAttributes}
	if got := s.functionIDs(); !reflect.DeepEqual(got, want) {
		t.Errorf("request sequence = %#04x, want %#04x", got, want)
	}
	if c.InTransaction() {
		t.Error("still in a transaction after Commit")
	}
}

func TestFailedCommitRollsBack(t *testing.T) {
	s := newFakeServer(t, handlers{
		fnCommit: func(req *fakeRequest) *fakeReply {
			return &fakeReply{errorClass: errorClassSQL, returnCode: -7008}
		},
	}.with(t))
	c := connect(t, s, Options{})
	ctx := context.Background()
	if err := c.Begin(ctx, IsolationReadUncommitted); err != nil {
		t.Fatal(err)
	}
	err := c.Commit(ctx)
	var dbErr *Error
	if !errors.As(err, &dbErr) || dbErr.SQLCode() != -7008 {
		t.Fatalf("Commit error = %v, want SQLCODE -7008", err)
	}
	want := []uint16{fnSetAttributes, fnSetAttributes, fnCommit, fnRollback, fnSetAttributes}
	if got := s.functionIDs(); !reflect.DeepEqual(got, want) {
		t.Errorf("request sequence = %#04x, want %#04x", got, want)
	}
}

func TestDatabaseSQL(t *testing.T) {
	s := selectServer(t)
	db := sql.OpenDB(NewConnector(s.dial(), "TESTUSER", "secret", Options{}))
	defer db.Close()

	var (
		id, name string
		amt      string
		dt       time.Time
		qty      sql.NullInt64
	)
	err := db.QueryRowContext(context.Background(), "SELECT ID, NAME, AMT, DT, QTY FROM T WHERE ID > ?", "A0").Scan(&id, &name, &amt, &dt, &qty)
	if err != nil {
		t.Fatalf("QueryRow: %v", err)
	}
	if id != "A1   " || name != "alpha" || amt != "12.50" || !qty.Valid || qty.Int64 != 7 {
		t.Errorf("scanned %q %q %q %v %v", id, name, amt, dt, qty)
	}

	rows, err := db.Query("SELECT ID, NAME, AMT, DT, QTY FROM T WHERE ID > ?", "A0")
	if err != nil {
		t.Fatal(err)
	}
	types, _ := rows.ColumnTypes()
	if types[2].DatabaseTypeName() != "DECIMAL" {
		t.Errorf("column type = %s, want DECIMAL", types[2].DatabaseTypeName())
	}
	if p, sc, ok := types[2].DecimalSize(); !ok || p != 7 || sc != 2 {
		t.Errorf("DecimalSize = %d,%d,%v", p, sc, ok)
	}
	n := 0
	for rows.Next() {
		n++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if n != 3 {
		t.Errorf("read %d rows, want 3", n)
	}
}

func TestIOFailureBreaksConnectionWithoutRetry(t *testing.T) {
	var executes atomic.Int32
	s := newFakeServer(t, handlers{
		fnPrepareDescribe: func(req *fakeRequest) *fakeReply { return &fakeReply{} },
		fnExecute: func(req *fakeRequest) *fakeReply {
			executes.Add(1)
			time.Sleep(300 * time.Millisecond) // longer than the client's IOTimeout below
			return &fakeReply{}
		},
	}.with(t))
	dial := s.dial()
	dial.IOTimeout = 100 * time.Millisecond
	db := sql.OpenDB(NewConnector(dial, "TESTUSER", "secret", Options{}))
	defer db.Close()

	_, err := db.Exec("UPDATE T SET X = 1")
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if errors.Is(err, driver.ErrBadConn) {
		t.Errorf("timed-out execute surfaced as ErrBadConn (which database/sql retries): %v", err)
	}
	if n := executes.Load(); n != 1 {
		t.Errorf("execute reached the server %d times, want exactly 1", n)
	}
}

func TestBrokenConnRejectsFurtherUse(t *testing.T) {
	s := newFakeServer(t, handlers{}.with(t))
	c := connect(t, s, Options{})
	c.broken = true
	if _, err := c.Prepare(context.Background(), "VALUES 1"); !errors.Is(err, ErrConnBroken) {
		t.Errorf("Prepare on broken conn = %v, want ErrConnBroken", err)
	}
	d := &driverConn{c: c}
	if _, err := d.Prepare("VALUES 1"); err != driver.ErrBadConn {
		t.Errorf("driver Prepare on broken conn = %v, want driver.ErrBadConn", err)
	}
	if d.IsValid() {
		t.Error("IsValid = true for a broken conn")
	}
}

func TestParseDSN(t *testing.T) {
	c, err := ParseDSN("jt400://CMSUSER:p%40ss@10.175.10.33?naming=system&schema=QGPL&timeout=5s&iotimeout=90s&tls=true&location=Asia/Jakarta&blocksize=65536")
	if err != nil {
		t.Fatal(err)
	}
	if c.UserID != "CMSUSER" || c.Password != "p@ss" || c.Dial.Host != "10.175.10.33" {
		t.Errorf("user/host = %q %q %q", c.UserID, c.Password, c.Dial.Host)
	}
	if !c.Options.SystemNaming || c.Options.DefaultSchema != "QGPL" || c.Options.BlockSize != 65536 {
		t.Errorf("options = %+v", c.Options)
	}
	if c.Dial.Timeout != 5*time.Second || c.Dial.IOTimeout != 90*time.Second || c.Dial.TLSConfig == nil {
		t.Errorf("dial = %+v", c.Dial)
	}
	if c.Options.Location.String() != "Asia/Jakarta" {
		t.Errorf("location = %v", c.Options.Location)
	}
	for _, bad := range []string{
		"postgres://u:p@h", "jt400://h", "jt400://u:p@h?naming=odd", "jt400://u:p@h?bogus=1", "jt400://u:p@h:x",
	} {
		if _, err := ParseDSN(bad); err == nil {
			t.Errorf("ParseDSN(%q): expected an error", bad)
		}
	}
}
