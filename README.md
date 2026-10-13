# jt400-go

Native Go client library for a subset of IBM i (AS/400) host server protocols,
reimplemented from scratch based on the publicly documented wire behavior of
IBM's [JTOpen](https://github.com/IBM/JTOpen) (IBM Toolbox for Java). This is
an independent, pure-Go reimplementation — it does not embed, link against,
or transpile any JTOpen/JT400 source code, and it is not affiliated with or
endorsed by IBM. JTOpen's source is used only as a functional reference for
understanding the (largely undocumented) wire formats.

## Installation

```bash
go get github.com/win-cahyo/jt400-go
```

```go
import (
	"github.com/win-cahyo/jt400-go/as400"
	"github.com/win-cahyo/jt400-go/signon"
	"github.com/win-cahyo/jt400-go/dtaq"
	"github.com/win-cahyo/jt400-go/rmtcmd"
	"github.com/win-cahyo/jt400-go/database"
)
```

Each service package is independent — import only the ones you use. See
[`examples/`](examples) for runnable end-to-end usage (`signon`, `rmtcmd`,
`database`).

## Scope

This library intentionally targets **only** the IBM i host servers needed
for typical application-integration use cases — not the full surface of
JTOpen (no DRDA, no IFS, no print server, no Swing/bean tooling, no
native/JNI paths that only apply when running inside the IBM i JVM):

| Server    | Port (TCP/SSL) | Purpose                                   | Status      |
|-----------|-----------------|--------------------------------------------|-------------|
| as-signon | 8476 / 9476     | Authentication (user/password → session)   | implemented |
| as-dtaq   | 8472 / 9472     | Data queue read/write (keyed & non-keyed)  | implemented |
| as-rmtcmd | 8475 / 9475     | Run CL command / call program              | implemented |
| as-database | 8471 / 9471   | SQL: prepared statements, cursors, commit (JTOpen's JDBC wire protocol) | implemented (subset) |

## Architecture

- [`as400/`](as400) — shared connection plumbing: TCP/TLS dial to a host
  server port, and the common host-server datastream framing (header +
  template + optional data) that as-signon, as-dtaq, and as-rmtcmd all build
  on top of.
- [`signon/`](signon) — as-signon client: connect, exchange server
  attributes, authenticate.
- [`dtaq/`](dtaq) — as-dtaq client: create/delete/clear a data queue, and
  read/write entries (plain and keyed).
- [`rmtcmd/`](rmtcmd) — as-rmtcmd client: start the remote command server job,
  run a CL command, call a program with parameters.
- [`database/`](database) — as-database client: prepare/execute SQL with `?`
  parameter markers, forward-only cursors, row counts, commit/rollback, and
  a `database/sql` driver (`"jt400"`) on top. Character data is converted
  client-side per column CCSID, using `golang.org/x/text`.

Each service package depends only on `as400/`, the standard library and
`golang.org/x/*` — no CGO, no JNI, no dependency on an IBM-provided native
client or ODBC driver.

## SQL (as-database)

Through `database/sql`:

```go
import (
	"database/sql"

	"github.com/win-cahyo/jt400-go/as400"
	"github.com/win-cahyo/jt400-go/database"
)

db := sql.OpenDB(database.NewConnector(
	as400.DialOptions{Host: "ibmi.example.com", Timeout: 10 * time.Second, IOTimeout: 90 * time.Second},
	"USER", password,
	database.Options{SystemNaming: true, Location: jakarta},
))
// or: sql.Open("jt400", "jt400://USER:PASSWORD@ibmi.example.com?naming=system&iotimeout=90s")

var status, desc string
err := db.QueryRowContext(ctx,
	"SELECT STATUS, RSDESC FROM QGPL.CMSBULK WHERE TRX_ID = ? AND TR_DATE = ?",
	trxID, trDate).Scan(&status, &desc)

res, err := db.ExecContext(ctx,
	"UPDATE JTGKNVSYA.CMSBDUE SET TYPE = '1', SPVID = ? WHERE TRX_ID = ?", spvID, trxID)
n, _ := res.RowsAffected()
```

Or directly with `database.Connect`, `Conn.Prepare`, `Stmt.Exec` / `Stmt.Query`
(see [`examples/database`](examples/database)).

Behavior worth knowing:

- **Pooling.** `database.Connect` is a single connection (one QZDASOINIT job);
  pooling comes from `*sql.DB`. The pool does not validate a connection when
  it hands it out, and a request on a connection the network silently
  dropped while idle fails rather than being retried (see *Retries* below).
  Set `db.SetConnMaxIdleTime` shorter than any firewall/server idle timeout
  on the path, so idle connections are closed before they can go stale.
- **Values.** DECIMAL/NUMERIC are returned as exact decimal strings
  (`"1500000.00"`), never `float64`; scan them into a `string` or a decimal
  type. CHAR keeps its trailing blanks (as JDBC's `getString` does). DATE and
  TIMESTAMP are `time.Time` in `Options.Location` (default UTC); TIME is an
  `"hh:mm:ss"` string. Parameters that would lose data (too long for the
  column, more digits than the precision, non-zero digits beyond the scale)
  are rejected, not truncated or rounded.
- **CCSIDs.** 37, 1047, 1140, 1200/13488 and 1208 are built in. Register any
  other column CCSID with `database.RegisterCCSID` before connecting, or the
  first statement touching that column fails with a clear error.
- **Transactions.** Autocommit with no commitment control (`*NONE`) is the
  default, as with JTOpen. `BeginTx` switches to commitment control
  (`*CHG` by default), which requires the changed tables to be journaled. A
  failed commit is followed by a rollback; if the connection's state cannot
  be restored it is discarded instead of being returned to the pool.
- **Retries.** `driver.ErrBadConn` (which makes `database/sql` retry on a new
  connection) is only returned when nothing was sent on a broken connection.
  A request that timed out or failed mid-exchange returns its real error, so
  an INSERT or UPDATE is never silently run twice.
- **Not supported:** LOB locators, DECFLOAT, XML, arrays, BOOLEAN, stored
  procedure result sets (CALL works as an Exec), scrollable or updatable
  cursors, batch execution, SQL packages, `LastInsertId` (use
  `SELECT ... FROM FINAL TABLE (INSERT ...)`), named parameters, and
  library-list management (use `Options.DefaultSchema`, or
  `CALL QSYS2.QCMDEXC('ADDLIBLE ...')`).

## Long-lived / pooled connections

By default a `Connection` (and the `signon`/`dtaq`/`rmtcmd` clients built
on it) never times out an individual `Call` once established —
`DialOptions.Timeout` only bounds the initial dial. If your application
holds a `Connection` open and reuses it across many calls (e.g. an
application-managed connection pool, to avoid paying the dial + logon
handshake on every request), set `DialOptions.IOTimeout` too: without it,
a host server that stops responding mid-exchange (dropped route, an
overloaded server, a firewall silently dropping packets) hangs the calling
goroutine — and, in a pool, strands that connection — forever.

## Status

All targeted servers are implemented and unit-tested (wire encoding,
LL/CP parameter framing, and reply parsing verified against synthetic data
built from the exact JTOpen source byte offsets — see each package's
`*_test.go`; `database` additionally runs its full request sequence against
an in-process fake as-database server). What that testing **cannot** cover,
for lack of a live IBM i system to test against:

- The password-substitute derivations (DES for password level 0/1, SHA-1
  for level 2/3, SHA-512/PBKDF2 for level 4) are transcribed field-for-field
  from the Java source and cross-checked against known DES/PBKDF2 test
  vectors, but the full derivation chain has not been exercised against a
  real signon. Level 0/1 (legacy DES) in particular carries the most risk.
- `rmtcmd.RunCommand` only implements the Unicode command-text path (server
  datastream level 10+, i.e. V6R1/2008 onward) — see [`rmtcmd/wire.go`](rmtcmd/wire.go)
  for why the pre-Unicode EBCDIC path isn't implemented.
- `rmtcmd.CallProgram` doesn't send RLE-compressed input (harmless, just
  less bandwidth-efficient for >1KB parameters). It does decompress
  RLE-compressed *output* (the host server tends to use it for large,
  mostly-blank-padded character parameters) — see
  [`rmtcmd/rle.go`](rmtcmd/rle.go), transcribed from JTOpen's
  `DataStreamCompression.decompressRLE`.
- `database` has so far been verified against one real system (IBM i 7.4,
  server CCSID 37) for logon, SET_ATTRIBUTES and a SELECT without parameter
  markers: CHAR, NUMERIC (zoned) and column descriptions decode correctly.
  Not yet exercised against a real server: parameter markers (CHANGE_DESCRIPTOR
  and parameter data), multi-block fetches, INSERT/UPDATE row counts, and
  transactions. The request layouts follow JTOpen's `AS400JDBCConnectionImpl`,
  `AS400JDBCStatement` and `AS400JDBCPreparedStatementImpl`, but this client
  requests the *extended* (V4R4+) data formats rather than JTOpen's current
  super-extended ones (it can read either), and skips several optional
  attributes JTOpen sends (client support level, decimal precision, client
  info), relying on server defaults.
- Free-text fields (message text/help, queue text descriptions) are decoded
  with this library's restricted EBCDIC table (letters, digits, space,
  `$ # @`) and show `?` for characters outside it — see
  [`as400/auth/ebcdic.go`](as400/auth/ebcdic.go).

Before pointing this at a production system, test it against a real IBM i
system first, ideally starting with a non-destructive operation (e.g.
`signon.Client.Authenticate`, `dtaq.Queue.Attributes`, or a `VALUES 1`
query through `database`).

## Disclaimer

Communicating with IBM i host servers involves transmitting credentials.
Test against a non-production system before trusting this library with
real credentials. IBM i, AS/400, and DB2 for i are trademarks of IBM. This
project has no affiliation with IBM.
