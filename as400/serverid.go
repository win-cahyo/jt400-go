package as400

// ServerID identifies the destination host server in a datastream header.
// Every valid ID has 0xE0 as its high byte; readers reject anything else.
type ServerID uint16

const (
	ServerSignon        ServerID = 0xE009 // as-signon, TCP 8476 / SSL 9476
	ServerDataQueue     ServerID = 0xE007 // as-dtaq,   TCP 8472 / SSL 9472
	ServerRemoteCommand ServerID = 0xE008 // as-rmtcmd, TCP 8475 / SSL 9475
)

// Well-known TCP ports for the host servers this library supports. Use the
// Secure variant when dialing with a non-nil tls.Config.
const (
	PortSignonPlain  = 8476
	PortSignonSecure = 9476

	PortDataQueuePlain  = 8472
	PortDataQueueSecure = 9472

	PortRemoteCommandPlain  = 8475
	PortRemoteCommandSecure = 9475
)
