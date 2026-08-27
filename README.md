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
)
```

Each service package is independent — import only the ones you use. See
[`examples/`](examples) for runnable end-to-end usage (`signon`, `rmtcmd`).

## Scope

This library intentionally targets **only** the three IBM i host servers
needed for typical application-integration use cases — not the full surface
of JTOpen (no JDBC/DRDA, no IFS, no print server, no Swing/bean tooling, no
native/JNI paths that only apply when running inside the IBM i JVM):

| Server    | Port (TCP/SSL) | Purpose                                   | Status      |
|-----------|-----------------|--------------------------------------------|-------------|
| as-signon | 8476 / 9476     | Authentication (user/password → session)   | implemented |
| as-dtaq   | 8472 / 9472     | Data queue read/write (keyed & non-keyed)  | implemented |
| as-rmtcmd | 8475 / 9475     | Run CL command / call program              | implemented |

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

Each service package depends only on `as400/` and the standard library —
no CGO, no JNI, no dependency on an IBM-provided native client.

## Status

All three targeted servers are implemented and unit-tested (wire encoding,
LL/CP parameter framing, and reply parsing verified against synthetic data
built from the exact JTOpen source byte offsets — see each package's
`*_test.go`). What that testing **cannot** cover, for lack of a live IBM i
system to test against:

- The password-substitute derivations (DES for password level 0/1, SHA-1
  for level 2/3, SHA-512/PBKDF2 for level 4) are transcribed field-for-field
  from the Java source and cross-checked against known DES/PBKDF2 test
  vectors, but the full derivation chain has not been exercised against a
  real signon. Level 0/1 (legacy DES) in particular carries the most risk.
- `rmtcmd.RunCommand` only implements the Unicode command-text path (server
  datastream level 10+, i.e. V6R1/2008 onward) — see [`rmtcmd/wire.go`](rmtcmd/wire.go)
  for why the pre-Unicode EBCDIC path isn't implemented.
- `rmtcmd.CallProgram` doesn't send RLE-compressed input (harmless, just
  less bandwidth-efficient for >1KB parameters) and returns an explicit
  error rather than mis-decoding if the server sends RLE-compressed output.
- Free-text fields (message text/help, queue text descriptions) are decoded
  with this library's restricted EBCDIC table (letters, digits, space,
  `$ # @`) and show `?` for characters outside it — see
  [`as400/auth/ebcdic.go`](as400/auth/ebcdic.go).

Before pointing this at a production system, test it against a real IBM i
system first, ideally starting with a non-destructive operation (e.g.
`signon.Client.Authenticate`, `dtaq.Queue.Attributes`).

## Disclaimer

Communicating with IBM i host servers involves transmitting credentials.
Test against a non-production system before trusting this library with
real credentials. IBM i, AS/400, and DB2 for i are trademarks of IBM. This
project has no affiliation with IBM.
