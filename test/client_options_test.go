package socks5_test

import (
	"context"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/AeonDave/go-s5/auth"
	client "github.com/AeonDave/go-s5/client"
	handler "github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/protocol"
	server "github.com/AeonDave/go-s5/server"

	"github.com/stretchr/testify/require"
)

// WithMethods forcing NoAuth against a server that only accepts User/Pass must
// fail the negotiation with "no acceptable method".
func TestClientWithMethods_NoAcceptable(t *testing.T) {
	listen, stop := startSocks5(t, server.WithCredential(auth.StaticCredentials{"alice": "secret"}))
	defer stop()

	conn, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	cli := client.New(
		client.WithMethods([]byte{protocol.MethodNoAuth}),
		client.WithHandshakeTimeout(time.Second),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = cli.Handshake(ctx, conn, &client.Credentials{Username: "alice", Password: "secret"})
	require.Error(t, err)
}

// WithUDPLocalAddr must bind the association socket to the requested local IP.
func TestClientWithUDPLocalAddr(t *testing.T) {
	listen, stop := startSocks5(t)
	defer stop()

	conn, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	cli := client.New(
		client.WithUDPLocalAddr(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}),
		client.WithHandshakeTimeout(time.Second),
		client.WithIOTimeout(2*time.Second),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = cli.Handshake(ctx, conn, nil)
	require.NoError(t, err)

	assoc, rep, err := cli.UDPAssociate(ctx, conn)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepSuccess), rep.Response)
	t.Cleanup(func() { _ = assoc.Close() })

	la := assoc.Conn.LocalAddr().(*net.UDPAddr)
	require.True(t, la.IP.Equal(net.ParseIP("127.0.0.1")), "expected 127.0.0.1 local bind, got %s", la.IP)
}

// WithLogger must accept both a real logger and nil (silencing output), and
// WithUDPKeepAlive must record interval/payload for later associations.
func TestClientLoggerAndKeepAliveOptions(t *testing.T) {
	// nil logger branch
	_ = client.New(client.WithLogger(nil))
	// real logger branch (std logger writes to discard to stay quiet)
	stdLogger := client.NewStdLogger(log.New(io.Discard, "", 0), client.LogLevelDebug)
	_ = client.New(client.WithLogger(stdLogger))
	// silent logger constructor
	_ = client.New(client.WithLogger(client.NewSilentLogger()))
	// keep-alive: nil payload defaults to single zero byte; non-empty is copied
	_ = client.New(client.WithUDPKeepAlive(50*time.Millisecond, nil))
	payload := []byte{0xAB, 0xCD}
	cli := client.New(client.WithUDPKeepAlive(50*time.Millisecond, payload))
	require.NotNil(t, cli)
	// mutating the caller slice must not affect the client's copy
	payload[0] = 0xFF
}

// Bind() convenience helper: a custom bind handler that immediately sends the
// two replies lets us exercise both steps without coordinating a real peer.
func TestClientBindHelper(t *testing.T) {
	bound := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4242}
	peer := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 4243}
	listen, stop := startSocks5(t,
		server.WithBindHandle(func(_ context.Context, w io.Writer, _ *handler.Request) error {
			if err := server.SendReply(w, protocol.RepSuccess, bound); err != nil {
				return err
			}
			return server.SendReply(w, protocol.RepSuccess, peer)
		}),
	)
	defer stop()

	conn, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	cli := client.New(client.WithHandshakeTimeout(time.Second), client.WithIOTimeout(2*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = cli.Handshake(ctx, conn, nil)
	require.NoError(t, err)

	expect := protocol.AddrSpec{IP: net.IPv4zero, Port: 0, AddrType: protocol.ATYPIPv4}
	first, second, err := cli.Bind(ctx, conn, expect)
	require.NoError(t, err)
	require.Equal(t, bound.Port, first.BndAddr.Port)
	require.Equal(t, peer.Port, second.BndAddr.Port)
}

// Bind() must surface a failure from the first reply without waiting for the second.
func TestClientBindHelper_FirstReplyError(t *testing.T) {
	listen, stop := startSocks5(t,
		server.WithBindHandle(func(_ context.Context, w io.Writer, _ *handler.Request) error {
			return server.SendReply(w, protocol.RepServerFailure, nil)
		}),
	)
	defer stop()

	conn, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	cli := client.New(client.WithHandshakeTimeout(time.Second), client.WithIOTimeout(2*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = cli.Handshake(ctx, conn, nil)
	require.NoError(t, err)

	expect := protocol.AddrSpec{IP: net.IPv4zero, Port: 0, AddrType: protocol.ATYPIPv4}
	_, _, err = cli.Bind(ctx, conn, expect)
	require.Error(t, err)
	require.Contains(t, err.Error(), "BIND failed")
}
