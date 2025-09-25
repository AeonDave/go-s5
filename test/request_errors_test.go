package socks5_test

import (
	"bytes"
	socks5 "go-s5"
	"go-s5/internal/protocol"
	"io"
	"log"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnsupportedCommand(t *testing.T) {
	listen, stop := startSocks5(t,
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)
	defer stop()

	c, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(c net.Conn) {
		_ = c.Close()
	}(c)

	// handshake NoAuth
	_, _ = c.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	m := make([]byte, 2)
	_, err = io.ReadFull(c, m)
	require.NoError(t, err)

	// Craft unsupported command 0x09 with IPv4 addr 127.0.0.1:1
	req := bytes.NewBuffer(nil)
	req.Write([]byte{protocol.VersionSocks5, 0x09, 0x00, protocol.ATYPIPv4, 127, 0, 0, 1, 0, 1})
	_, _ = c.Write(req.Bytes())
	rep, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepCommandNotSupported), rep.Response)
}

func TestInvalidAddrType(t *testing.T) {
	listen, stop := startSocks5(t,
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)
	defer stop()

	c, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(c net.Conn) {
		_ = c.Close()
	}(c)

	// handshake NoAuth
	_, _ = c.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	m := make([]byte, 2)
	_, err = io.ReadFull(c, m)
	require.NoError(t, err)

	// CONNECT with ATYP=0x05 (invalid)
	req := bytes.NewBuffer(nil)
	req.Write([]byte{protocol.VersionSocks5, protocol.CommandConnect, 0x00, 0x05})
	req.Write([]byte{1, 2}) // arbitrary tail; server should reject before reading
	_, _ = c.Write(req.Bytes())
	rep, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepAddrTypeNotSupported), rep.Response)
}
