package socks5_test

import (
	"net"
	"testing"
	"time"

	server "github.com/AeonDave/go-s5/server"
)

// Connection that does not send handshake should be closed after handshake timeout
func TestHandshakeTimeout(t *testing.T) {
	listen, stop := startSocks5(t,
		server.WithHandshakeTimeout(100*time.Millisecond),
	)
	defer stop()

	c, err := net.Dial("tcp", listen)
	if err != nil {
		t.Fatal(err)
	}
	defer func(c net.Conn) {
		_ = c.Close()
	}(c)
	// wait past timeout
	time.Sleep(250 * time.Millisecond)
	// a write should fail or subsequent read should error as the server closed
	_, err = c.Write([]byte{0x00})
	if err == nil {
		_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		buf := make([]byte, 1)
		_, err = c.Read(buf)
		_ = c.SetReadDeadline(time.Time{})
	}
	if err == nil {
		t.Fatal("expected connection to be closed by timeout")
	}
}
