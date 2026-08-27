package as400

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/win-cahyo/jt400-go/as400/auth"
)

// StartServerSession is the result of Logon: the generic two-step host-
// server logon (JTOpen's AS400XChgRandSeedDS + AS400StrSvrDS) that every
// Client Access host server except as-signon requires before any service-
// specific request can be sent. as-signon instead uses its own exchange-
// attributes + signon-info exchange — see the signon package.
type StartServerSession struct {
	// PasswordLevel is negotiated independently by this handshake (the
	// "server attributes" byte of the exchange-random-seeds reply doubles
	// as the password level on V5R1 and later) — it does not need to be
	// learned from a prior as-signon connection.
	PasswordLevel auth.PasswordLevel
	// JobName is the server job started to service this connection, when
	// the server returned one.
	JobName string
}

// Logon performs the exchange-random-seeds and start-server requests
// against a freshly dialed Connection, authenticating with userID/password.
// serverID selects the target host server (e.g. ServerDataQueue,
// ServerRemoteCommand).
func Logon(conn *Connection, serverID ServerID, userID, password string) (*StartServerSession, error) {
	var clientSeed [8]byte
	binary.BigEndian.PutUint64(clientSeed[:], uint64(time.Now().UnixMilli()))

	reply, err := conn.Call(buildXChgRandSeedRequest(serverID, clientSeed))
	if err != nil {
		return nil, fmt.Errorf("as400: exchange random seeds: %w", err)
	}
	serverSeed, passwordLevel, err := parseXChgRandSeedReply(reply)
	if err != nil {
		return nil, err
	}

	authBytes, err := auth.EncryptPassword(passwordLevel, userID, password, clientSeed, serverSeed)
	if err != nil {
		return nil, err
	}
	userIDBytes, err := auth.EncodeEBCDIC10(strings.ToUpper(userID))
	if err != nil {
		return nil, fmt.Errorf("as400: user id: %w", err)
	}

	reply, err = conn.Call(buildStartServerRequest(serverID, userIDBytes, authBytes))
	if err != nil {
		return nil, fmt.Errorf("as400: start server: %w", err)
	}
	jobName, err := parseStartServerReply(reply)
	if err != nil {
		return nil, err
	}

	return &StartServerSession{PasswordLevel: passwordLevel, JobName: jobName}, nil
}

// buildXChgRandSeedRequest builds the "exchange random seed" request
// (opcode 0x7001). The client seed is sent as a raw 8-byte template field,
// not an LL/CP parameter — unlike as-signon's own exchange-attributes
// request, which wraps its client seed in an LL/CP entry.
func buildXChgRandSeedRequest(serverID ServerID, clientSeed [8]byte) Request {
	return Request{
		ServerID:    serverID,
		HeaderID:    AttrHeaderID(0x03), // client attrs: SHA-1/pwdlvl4/AAF support
		TemplateLen: 8,
		ReqRepID:    0x7001,
		Body:        clientSeed[:],
	}
}

func parseXChgRandSeedReply(reply *Reply) (serverSeed [8]byte, passwordLevel auth.PasswordLevel, err error) {
	rc, ok := reply.RC()
	if !ok {
		return serverSeed, 0, fmt.Errorf("as400: exchange-random-seeds reply too short")
	}
	if rc != 0 {
		return serverSeed, 0, fmt.Errorf("as400: exchange random seeds failed, rc=%#08x", rc)
	}
	if len(reply.Body) < 12 {
		return serverSeed, 0, fmt.Errorf("as400: exchange-random-seeds reply missing server seed")
	}
	copy(serverSeed[:], reply.Body[4:12])
	// The reply's "server attributes" byte (the low byte of HeaderID) is
	// documented by JTOpen (AS400XChgRandSeedReplyDS.getServerAttributes)
	// as doubling as the password level on V5R1 and later systems.
	passwordLevel = auth.PasswordLevel(reply.ServerAttr())
	return serverSeed, passwordLevel, nil
}

// buildStartServerRequest builds the "start server" request (opcode
// 0x7002) that actually starts the target host server's job, carrying the
// encrypted password/auth bytes and the EBCDIC user ID.
func buildStartServerRequest(serverID ServerID, userIDBytes [10]byte, authBytes []byte) Request {
	var authType byte
	switch len(authBytes) {
	case 8:
		authType = 0x01 // DES password substitute
	case 20:
		authType = 0x03 // SHA-1 password substitute
	default:
		authType = 0x07 // SHA-512 password substitute
	}

	body := []byte{authType, 0x01} // byte 1: "send reply" = true
	body = append(body, EncodeParams(Param{CodePoint: 0x1105, Data: authBytes})...)
	body = append(body, EncodeParams(Param{CodePoint: 0x1104, Data: userIDBytes[:]})...)

	return Request{
		ServerID:    serverID,
		HeaderID:    AttrHeaderID(0x02), // client attrs: can get job info back
		TemplateLen: 2,
		ReqRepID:    0x7002,
		Body:        body,
	}
}

func parseStartServerReply(reply *Reply) (jobName string, err error) {
	rc, ok := reply.RC()
	if !ok {
		return "", fmt.Errorf("as400: start-server reply too short")
	}
	if rc != 0 {
		return "", fmt.Errorf("as400: start server failed, rc=%#08x", rc)
	}
	if len(reply.Body) < 4 {
		return "", nil
	}
	params, err := DecodeParams(reply.Body[4:])
	if err != nil {
		return "", fmt.Errorf("as400: decode start-server reply: %w", err)
	}
	// CP 0x111F carries a 4-byte CCSID before the text (a 10-byte entry
	// header), same convention as as-signon's job name field — see
	// AS400StrSvrReplyDS.getJobNameBytes(), which reads from offset+10.
	if d, ok := Find(params, 0x111F); ok && len(d) >= 4 {
		return strings.TrimRight(auth.DecodeEBCDICLossy(d[4:]), " "), nil
	}
	return "", nil
}
