# jt400-go

Native Go client library for a subset of IBM i (AS/400) host server protocols,
reimplemented from scratch based on the publicly documented wire behavior of
IBM's [JTOpen](https://github.com/IBM/JTOpen) (IBM Toolbox for Java). This is
an independent, pure-Go reimplementation — it does not embed, link against,
or transpile any JTOpen/JT400 source code, and it is not affiliated with or
endorsed by IBM. JTOpen's source is used only as a functional reference for
understanding the (largely undocumented) wire formats.

## Scope

This library intentionally targets **only** the three IBM i host servers
needed for typical application-integration use cases — not the full surface
of JTOpen (no JDBC/DRDA, no IFS, no print server, no Swing/bean tooling, no
native/JNI paths that only apply when running inside the IBM i JVM):

| Server    | Port (TCP/SSL) | Purpose                                   | Status      |
|-----------|-----------------|--------------------------------------------|-------------|
| as-signon | 8476 / 9476     | Authentication (user/password → session)   | planned     |
| as-dtaq   | 8472 / 9472     | Data queue read/write (keyed & non-keyed)  | planned     |
| as-rmtcmd | 8475 / 9475     | Run CL command / call program              | planned     |

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

Early scaffolding. Wire-format details (packet header layout, opcodes,
password encryption scheme used during sign-on, per-service request/reply
payloads) are being derived from the JTOpen source and will be implemented
incrementally, starting with `as400/` (shared framing) and `signon/`
(everything else needs an authenticated session first).

## Disclaimer

Communicating with IBM i host servers involves transmitting credentials.
Until the sign-on package has been implemented and reviewed, do not use this
library against production systems. IBM i, AS/400, and DB2 for i are
trademarks of IBM. This project has no affiliation with IBM.
