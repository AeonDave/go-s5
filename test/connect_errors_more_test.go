package socks5_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"testing"

	socks5 "github.com/AeonDave/go-s5"
	"github.com/AeonDave/go-s5/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestCONNECT_DialTimeoutMapsToTTLExpired(t *testing.T) {
	listen, stop := startSocks5(t,
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		socks5.WithDial(func(_ context.Context, network, addr string) (net.Conn, error) {
			// simulate dial timeout
			return nil, errors.New("i/o timeout")
		}),
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

	// CONNECT to anything
	req := bytes.NewBuffer(nil)
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandConnect,
		DstAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 65000, AddrType: protocol.ATYPIPv4}}
	req.Write(head.Bytes())
	_, _ = c.Write(req.Bytes())
	rep, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepTTLExpired), rep.Response)
}

func TestCONNECT_NetworkUnreachableMapping(t *testing.T) {
	listen, stop := startSocks5(t,
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		socks5.WithDial(func(_ context.Context, network, addr string) (net.Conn, error) {
			// simulate unreachable network
			return nil, errors.New("network is unreachable")
		}),
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

	// CONNECT to anything
	req := bytes.NewBuffer(nil)
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandConnect,
		DstAddr: protocol.AddrSpec{IP: net.ParseIP("10.255.255.1"), Port: 80, AddrType: protocol.ATYPIPv4}}
	req.Write(head.Bytes())
	_, _ = c.Write(req.Bytes())
	rep, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepNetworkUnreachable), rep.Response)
}
