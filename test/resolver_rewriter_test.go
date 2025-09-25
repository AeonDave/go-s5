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
	"github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/internal/protocol"

	"github.com/stretchr/testify/require"
)

// resolver that always fails
type failingResolver struct{}

func (failingResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, errors.New("resolve failed")
}

// rewriter that forces destination
type rewriteTo struct {
	ip   net.IP
	port int
}

func (r rewriteTo) Rewrite(ctx context.Context, _ *handler.Request) (context.Context, *protocol.AddrSpec) {
	return ctx, &protocol.AddrSpec{IP: r.ip, Port: r.port, AddrType: protocol.ATYPIPv4}
}

func TestResolver_ErrorMapsToHostUnreachable(t *testing.T) {
	listen, stop := startSocks5(t,
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		socks5.WithResolver(failingResolver{}),
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

	// CONNECT to FQDN
	req := bytes.NewBuffer(nil)
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandConnect,
		DstAddr: protocol.AddrSpec{FQDN: "nonexistent.invalid", Port: 80, AddrType: protocol.ATYPDomain}}
	req.Write(head.Bytes())
	_, _ = c.Write(req.Bytes())
	rep, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepHostUnreachable), rep.Response)
}

func TestRewriter_OverridesDestination(t *testing.T) {
	// backend echo
	backend, stopBackend := startTCPBackend(t)
	defer stopBackend()

	listen, stop := startSocks5(t,
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		socks5.WithRewriter(rewriteTo{ip: net.ParseIP("127.0.0.1"), port: backend.Port}),
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

	// CONNECT to arbitrary unreachable port; rewrite will fix it
	req := bytes.NewBuffer(nil)
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandConnect,
		DstAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 1, AddrType: protocol.ATYPIPv4}}
	req.Write(head.Bytes())
	req.WriteString("ping")
	_, _ = c.Write(req.Bytes())

	// reply should be success thanks to rewrite
	rep, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepSuccess), rep.Response)
	// receive proxied echo
	buf := make([]byte, 4)
	_, err = io.ReadFull(c, buf)
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), buf)
}
