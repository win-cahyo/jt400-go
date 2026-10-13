package database

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/win-cahyo/jt400-go/as400"
)

// fakeServer is an in-process stand-in for an as-database host server. It
// answers the generic logon handshake itself and hands every as-database
// request to handle, replying only when the request's operation-result
// bitmap asks for a reply — so a client that waits for a reply the real
// server would never send hangs (and the test's IOTimeout fails it).
type fakeServer struct {
	t        *testing.T
	listener net.Listener
	handle   func(req *fakeRequest) *fakeReply

	mu       sync.Mutex
	requests []*fakeRequest
}

type fakeRequest struct {
	functionID uint16
	ors        uint32
	rpbID      uint16
	pmHandle   uint16
	params     []as400.Param
}

func (r *fakeRequest) param(cp uint16) []byte {
	d, _ := as400.Find(r.params, cp)
	return d
}

type fakeReply struct {
	errorClass uint16
	returnCode int32
	params     []as400.Param
}

func newFakeServer(t *testing.T, handle func(req *fakeRequest) *fakeReply) *fakeServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeServer{t: t, listener: l, handle: handle}
	go s.serve()
	t.Cleanup(func() { l.Close() })
	return s
}

func (s *fakeServer) dial() as400.DialOptions {
	addr := s.listener.Addr().(*net.TCPAddr)
	return as400.DialOptions{Host: addr.IP.String(), Port: addr.Port, IOTimeout: 2 * time.Second}
}

func (s *fakeServer) functionIDs() []uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]uint16, len(s.requests))
	for i, r := range s.requests {
		ids[i] = r.functionID
	}
	return ids
}

func (s *fakeServer) last(functionID uint16) *fakeRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.requests) - 1; i >= 0; i-- {
		if s.requests[i].functionID == functionID {
			return s.requests[i]
		}
	}
	return nil
}

func (s *fakeServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.serveConn(conn)
	}
}

func (s *fakeServer) serveConn(conn net.Conn) {
	defer conn.Close()
	for {
		in, err := as400.ReadReply(conn) // requests share the reply framing
		if err != nil {
			return
		}
		var out *as400.Request
		switch in.ReqRepID {
		case 0x7001: // exchange random seeds: password level 2 (SHA-1)
			body := make([]byte, 12)
			copy(body[4:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
			out = &as400.Request{ServerID: in.ServerID, HeaderID: 0x0002, ReqRepID: 0xF001, Body: body}
		case 0x7002: // start server
			out = &as400.Request{ServerID: in.ServerID, ReqRepID: 0xF002, Body: make([]byte, 4)}
		default:
			req := decodeFakeRequest(s.t, in)
			s.mu.Lock()
			s.requests = append(s.requests, req)
			s.mu.Unlock()
			rep := s.handle(req)
			if req.ors == 0 {
				if rep != nil {
					s.t.Errorf("handler returned a reply to no-reply request %#04x", req.functionID)
				}
				continue
			}
			if rep == nil {
				rep = &fakeReply{}
			}
			out = rep.encode(in.ServerID)
		}
		out.Correlation = in.Correlation
		if _, err := conn.Write(out.Encode()); err != nil {
			return
		}
	}
}

func decodeFakeRequest(t *testing.T, in *as400.Reply) *fakeRequest {
	b := in.Body
	if in.ServerID != as400.ServerDatabase || in.TemplateLen != templateLength || len(b) < templateLength {
		t.Errorf("malformed as-database request %#04x: server %#04x template %d", in.ReqRepID, in.ServerID, in.TemplateLen)
		return &fakeRequest{functionID: in.ReqRepID}
	}
	req := &fakeRequest{
		functionID: in.ReqRepID,
		ors:        binary.BigEndian.Uint32(b[0:4]),
		rpbID:      binary.BigEndian.Uint16(b[14:16]),
		pmHandle:   binary.BigEndian.Uint16(b[16:18]),
	}
	if a, c := binary.BigEndian.Uint16(b[8:10]), binary.BigEndian.Uint16(b[10:12]); a != req.rpbID || c != req.rpbID {
		t.Errorf("request %#04x: ORS handles %d/%d differ from RPB handle %d", in.ReqRepID, a, c, req.rpbID)
	}
	params, err := as400.DecodeParams(b[templateLength:])
	if err != nil {
		t.Errorf("request %#04x: %v", in.ReqRepID, err)
	}
	if n := int(binary.BigEndian.Uint16(b[18:20])); n != len(params) {
		t.Errorf("request %#04x: parameter count %d, found %d", in.ReqRepID, n, len(params))
	}
	req.params = params
	return req
}

func (r *fakeReply) encode(serverID as400.ServerID) *as400.Request {
	body := make([]byte, templateLength)
	binary.BigEndian.PutUint16(body[14:16], r.errorClass)
	binary.BigEndian.PutUint32(body[16:20], uint32(r.returnCode))
	body = append(body, as400.EncodeParams(r.params...)...)
	return &as400.Request{ServerID: serverID, TemplateLen: templateLength, ReqRepID: 0x2800, Body: body}
}

// Reply-building helpers.

func ebcdic(t *testing.T, s string) []byte {
	t.Helper()
	b, err := encodeString(37, s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func serverAttributesParam(t *testing.T) as400.Param {
	a := make([]byte, 120)
	binary.BigEndian.PutUint16(a[19:21], 37)
	copy(a[50:60], ebcdic(t, "V7R4M0  10"))
	copy(a[88:114], ebcdic(t, "QZDASOINITQUSER     123456"))
	return as400.Param{CodePoint: cpServerAttributes, Data: append([]byte{0, 37}, a...)}
}

func formatParam(t *testing.T, cp uint16, fields []field) as400.Param {
	b := encodeParameterFormat(fields)
	for i, f := range fields {
		fb := b[formatHeaderLength+i*formatFieldLength:]
		binary.BigEndian.PutUint16(fb[2:4], f.sqlType) // keep the described nullability
		if f.name != "" {
			name := ebcdic(t, f.name)
			binary.BigEndian.PutUint16(fb[30:32], uint16(len(name)))
			binary.BigEndian.PutUint16(fb[32:34], 37)
			copy(fb[34:], name)
		}
	}
	return as400.Param{CodePoint: cp, Data: b}
}

func sqlcaParam(rowCount int32, sqlState string, t *testing.T) as400.Param {
	ca := make([]byte, 136)
	binary.BigEndian.PutUint32(ca[104:108], uint32(rowCount))
	if sqlState != "" {
		copy(ca[131:136], ebcdic(t, sqlState))
	}
	return as400.Param{CodePoint: cpSQLCA, Data: ca}
}

// rowsParam encodes rows (each a slice of already-encoded fields, nil for
// NULL) as extended result data.
func rowsParam(fields []field, rows [][][]byte) as400.Param {
	rowSize := recordSize(fields)
	b := make([]byte, dataHeaderLength+len(rows)*(len(fields)*2+rowSize))
	binary.BigEndian.PutUint32(b[4:8], uint32(len(rows)))
	binary.BigEndian.PutUint16(b[8:10], uint16(len(fields)))
	binary.BigEndian.PutUint16(b[10:12], 2)
	binary.BigEndian.PutUint32(b[16:20], uint32(rowSize))
	dataStart := dataHeaderLength + len(rows)*len(fields)*2
	for r, row := range rows {
		off := dataStart + r*rowSize
		for c, v := range row {
			ind := dataHeaderLength + 2*(r*len(fields)+c)
			if v == nil {
				binary.BigEndian.PutUint16(b[ind:ind+2], 0xFFFF)
			} else {
				copy(b[off:], v)
			}
			off += fields[c].length
		}
	}
	return as400.Param{CodePoint: cpExtendedData, Data: b}
}

func messageParams(t *testing.T, id, text string) []as400.Param {
	idData := append([]byte{0, 37}, ebcdic(t, id)...)
	textBytes := ebcdic(t, text)
	textData := make([]byte, 4+len(textBytes))
	binary.BigEndian.PutUint16(textData[0:2], 37)
	binary.BigEndian.PutUint16(textData[2:4], uint16(len(textBytes)))
	copy(textData[4:], textBytes)
	return []as400.Param{{CodePoint: cpMessageID, Data: idData}, {CodePoint: cpFirstLevelText, Data: textData}}
}
