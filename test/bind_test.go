package socks5_test

import (
	"bytes"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"

	socks5 "github.com/AeonDave/go-s5"
	"github.com/AeonDave/go-s5/internal/protocol"

	"github.com/stretchr/testify/require"
)

// Expect two replies: first success with bind address, then TTLExpired after deadline.
func TestBIND_TTLExpired(t *testing.T) {
	listen, stop := startSocks5(t,
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		socks5.WithBindAcceptTimeout(150*time.Millisecond),
	)
	defer stop()

	c, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(c net.Conn) {
		_ = c.Close()
	}(c)

	// handshake: NoAuth
	_, _ = c.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	m := make([]byte, 2)
	_, err = io.ReadFull(c, m)
	require.NoError(t, err)

	// BIND to wildcard (port 0)
	req := bytes.NewBuffer(nil)
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandBind,
		DstAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 0, AddrType: protocol.ATYPIPv4}}
	req.Write(head.Bytes())
	_, _ = c.Write(req.Bytes())

	// First reply should be success with bind address
	rep1, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepSuccess), rep1.Response)

	// Second reply should be TTLExpired after timeout
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	rep2, err := protocol.ParseReply(c)
	_ = c.SetReadDeadline(time.Time{})
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepTTLExpired), rep2.Response)
}
