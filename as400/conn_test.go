package as400

import (
	"context"
	"errors"
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

// hungPeer starts a listener whose accepted connections read requests but
// never reply, and returns a Connection dialed to it.
func hungPeer(t *testing.T, ioTimeout time.Duration) *Connection {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		for {
			if _, err := conn.Read(buf); err != nil {
				return
			}
		}
	}()
	addr := listener.Addr().(*net.TCPAddr)
	conn, err := Dial(DialOptions{Host: addr.IP.String(), Port: addr.Port, IOTimeout: ioTimeout})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestCallContextCancelUnblocksRead(t *testing.T) {
	conn := hungPeer(t, 0) // no IOTimeout: only ctx can end the call
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)

	start := time.Now()
	_, err := conn.CallContext(ctx, Request{ServerID: ServerDatabase, ReqRepID: 1})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CallContext error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("CallContext took %v after cancel", elapsed)
	}
}

func TestCallContextDeadlineShorterThanIOTimeout(t *testing.T) {
	conn := hungPeer(t, 5*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := conn.CallContext(ctx, Request{ServerID: ServerDatabase, ReqRepID: 1})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CallContext error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("CallContext took %v; the ctx deadline should have won over IOTimeout", elapsed)
	}
}

func TestSendDoesNotWaitForReply(t *testing.T) {
	conn := hungPeer(t, 0)
	done := make(chan error, 1)
	go func() { done <- conn.Send(Request{ServerID: ServerDatabase, ReqRepID: 1}) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Send: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Send blocked waiting for a reply")
	}
	if conn.correlation != 1 {
		t.Errorf("correlation = %d after one Send, want 1", conn.correlation)
	}
}
