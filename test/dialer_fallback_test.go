package socks5_test

import (
	"bytes"
	"io"
	"log"
	"net"
	"os"
	"testing"

	"github.com/AeonDave/go-s5/internal/protocol"
	server "github.com/AeonDave/go-s5/server"

	"github.com/stretchr/testify/require"
)

func TestCONNECT_UsesCustomDialer(t *testing.T) {
	// backend
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func(l net.Listener) {
		_ = l.Close()
	}(l)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer func(c net.Conn) {
			_ = c.Close()
		}(c)
		buf := make([]byte, 4)
		_, err = io.ReadAtLeast(c, buf, 4)
		if err == nil {
			_, _ = c.Write([]byte("pong"))
		}
	}()
	backend := l.Addr().String()

	d := net.Dialer{}
	listen, stop := startSocks5(t,
		server.WithLogger(server.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		server.WithDialer(d), // should be used as no WithDial/WithDialAndRequest provided
	)
	defer stop()

	c, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(c net.Conn) {
		_ = c.Close()
	}(c)

	// NoAuth
	_, _ = c.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	m := make([]byte, 2)
	_, err = io.ReadFull(c, m)
	require.NoError(t, err)

	// CONNECT
	req := bytes.NewBuffer(nil)
	// connect to the backend address; with only WithDialer configured, server should use it
	backendAddr, _ := protocol.ParseAddrSpec(backend)
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandConnect, DstAddr: backendAddr}
	req.Write(head.Bytes())
	req.WriteString("ping")
	_, _ = c.Write(req.Bytes())

	rep, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepSuccess), rep.Response)

	out := make([]byte, 4)
	_, err = io.ReadFull(c, out)
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), out)
}
