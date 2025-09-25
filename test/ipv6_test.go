package socks5_test

import (
	"bytes"
	"fmt"
	socks5 "go-s5"
	"go-s5/internal/protocol"
	"io"
	"log"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func listenTCPv6(t *testing.T) (addr *net.TCPAddr, stop func()) {
	t.Helper()
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 not available: %v", err)
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
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
	return l.Addr().(*net.TCPAddr), func() { _ = l.Close(); <-stopped }
}

func TestIPv6_CONNECT(t *testing.T) {
	backend, stopB := listenTCPv6(t)
	defer stopB()

	listen, stop := startSocks5(t,
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
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

	req := bytes.NewBuffer(nil)
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandConnect,
		DstAddr: protocol.AddrSpec{IP: net.ParseIP("::1"), Port: backend.Port, AddrType: protocol.ATYPIPv6}}
	req.Write(head.Bytes())
	req.WriteString("ping")
	_, _ = c.Write(req.Bytes())

	rep, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepSuccess), rep.Response)
	// Should advertise IPv6 bind addr type
	require.Equal(t, byte(protocol.ATYPIPv6), rep.BndAddr.AddrType)

	buf := make([]byte, 4)
	_, err = io.ReadFull(c, buf)
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), buf)
}

func TestIPv6_BIND(t *testing.T) {
	// Control over IPv4, but BIND will listen on IPv6 if bindIP set
	listen, stop := startSocks5(t,
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		socks5.WithBindIP(net.IPv6loopback),
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

	req := bytes.NewBuffer(nil)
	req.Write((protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandBind,
		DstAddr: protocol.AddrSpec{IP: net.IPv6loopback, Port: 0, AddrType: protocol.ATYPIPv6}}).Bytes())
	_, _ = c.Write(req.Bytes())

	rep1, err := protocol.ParseReply(c)
	if err != nil || rep1.BndAddr.AddrType != protocol.ATYPIPv6 {
		t.Skip("IPv6 bind not supported; skipping")
	}

	// peer connects to bind address
	peer, err := net.Dial("tcp", net.JoinHostPort(rep1.BndAddr.IP.String(), fmt.Sprintf("%d", rep1.BndAddr.Port)))
	if err != nil {
		t.Skipf("IPv6 connect failed: %v", err)
	}
	defer func(peer net.Conn) {
		_ = peer.Close()
	}(peer)

	rep2, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepSuccess), rep2.Response)

	// client -> peer
	_, _ = c.Write([]byte("ping"))
	buf := make([]byte, 4)
	_, err = io.ReadFull(peer, buf)
	require.NoError(t, err)
	require.Equal(t, []byte("ping"), buf)
}
