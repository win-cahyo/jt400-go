package as400

import (
	"net"
	"testing"
	"time"
)

// TestIOTimeoutOnHungPeer verifies that a peer that accepts the connection
// but never sends a reply doesn't hang Call forever when IOTimeout is set —
// the exact bug a pooled, long-lived Connection would otherwise be exposed
// to if its AS400 host stops responding mid-exchange.
func TestIOTimeoutOnHungPeer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Accept the connection but never read or write anything,
		// simulating a host server that stops responding mid-exchange.
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(2 * time.Second)
	}()

	addr := listener.Addr().(*net.TCPAddr)
	conn, err := Dial(DialOptions{
		Host:      addr.IP.String(),
		Port:      addr.Port,
		IOTimeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	req := Request{
		ServerID: ServerID(0xE000),
		ReqRepID: 1,
		Body:     []byte{1, 2, 3},
	}

	start := time.Now()
	_, err = conn.Call(req)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	if elapsed >= time.Second {
		t.Fatalf("Call took %v, IOTimeout should have fired around 200ms", elapsed)
	}

	<-done
}
