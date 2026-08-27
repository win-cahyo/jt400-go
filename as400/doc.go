// Package as400 provides the shared TCP/TLS connection plumbing and common
// host-server datastream framing used by the signon, dtaq, and rmtcmd
// service packages.
//
// IBM i host servers (as-signon, as-central, as-dtaq, as-rmtcmd, and others)
// share a common packet envelope on top of which each service defines its
// own request/reply opcodes and payloads. That shared framing lives here so
// each service package only has to implement its own opcodes and payloads.
package as400
