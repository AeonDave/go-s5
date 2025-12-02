package socks5_test

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/AeonDave/go-s5/auth"
	socks5_handler "github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/internal/protocol"
	server "github.com/AeonDave/go-s5/server"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startTCPBackend(t *testing.T) (addr *net.TCPAddr, stop func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func(conn net.Conn) {
			_ = conn.Close()
		}(conn)
		buf := make([]byte, 4)
		_, err = io.ReadAtLeast(conn, buf, 4)
		if err == nil {
			_, _ = conn.Write([]byte("pong"))
		}
	}()
	return l.Addr().(*net.TCPAddr), func() { _ = l.Close(); <-stopped }
}

func startSocks5(t *testing.T, opts ...server.Option) (listen string, stop func()) {
	t.Helper()
	srv := server.New(opts...)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ln)
	}()
	// give it a moment to start
	time.Sleep(10 * time.Millisecond)
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }
}

func TestSOCKS5_Connect_OK(t *testing.T) {
	backendAddr, stopBackend := startTCPBackend(t)
	defer stopBackend()

	cator := auth.UserPassAuthenticator{Credentials: auth.StaticCredentials{"foo": "bar"}}
	listen, stop := startSocks5(t,
		server.WithAuthMethods([]auth.Authenticator{cator}),
		server.WithLogger(server.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		server.WithDialAndRequest(func(ctx context.Context, network, _ string, _ *socks5_handler.Request) (net.Conn, error) {
			return net.Dial(network, backendAddr.String())
		}),
	)
	defer stop()

	conn, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	// Build client bytes: method offer + userpass + connect request + payload
	req := bytes.NewBuffer(nil)
	req.Write([]byte{protocol.VersionSocks5, 2, protocol.MethodNoAuth, protocol.MethodUserPassAuth})
	up, err := protocol.NewUserPassRequest(protocol.UserPassAuthVersion, []byte("foo"), []byte("bar"))
	require.NoError(t, err)
	req.Write(up.Bytes())
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandConnect, DstAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: backendAddr.Port, AddrType: protocol.ATYPIPv4}}
	req.Write(head.Bytes())
	req.WriteString("ping")
	_, _ = conn.Write(req.Bytes())

	// Read method choice
	m := make([]byte, 2)
	_, err = io.ReadFull(conn, m)
	require.NoError(t, err)
	assert.Equal(t, []byte{protocol.VersionSocks5, protocol.MethodUserPassAuth}, m)
	// Read auth status
	a := make([]byte, 2)
	_, err = io.ReadFull(conn, a)
	require.NoError(t, err)
	assert.Equal(t, []byte{protocol.UserPassAuthVersion, protocol.AuthSuccess}, a)
	// Read reply header
	rep, err := protocol.ParseReply(conn)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.VersionSocks5), rep.Version)
	require.Equal(t, byte(protocol.RepSuccess), rep.Response)
	// Read proxied payload
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, []byte("pong"), buf)
}

// Custom handler should short-circuit and write its own payload
func TestSOCKS5_Connect_CustomHandler(t *testing.T) {
	backendAddr, stopBackend := startTCPBackend(t)
	defer stopBackend()

	cator := auth.UserPassAuthenticator{Credentials: auth.StaticCredentials{"foo": "bar"}}
	listen, stop := startSocks5(t,
		server.WithAuthMethods([]auth.Authenticator{cator}),
		server.WithLogger(server.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		server.WithDialAndRequest(func(ctx context.Context, network, _ string, _ *socks5_handler.Request) (net.Conn, error) {
			return net.Dial(network, backendAddr.String())
		}),
		server.WithConnectHandle(func(ctx context.Context, w io.Writer, _ *socks5_handler.Request) error {
			rsp := protocol.Reply{Version: protocol.VersionSocks5, Response: protocol.RepSuccess, BndAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), AddrType: protocol.ATYPIPv4}}
			if _, err := w.Write(rsp.Bytes()); err != nil {
				return err
			}
			_, _ = w.Write([]byte("gotcha!"))
			// try CloseWrite if available
			type cw interface{ CloseWrite() error }
			if cwi, ok := w.(cw); ok {
				_ = cwi.CloseWrite()
			}
			return nil
		}),
	)
	defer stop()

	conn, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	// handshake + userpass + CONNECT + payload
	req := bytes.NewBuffer(nil)
	req.Write([]byte{protocol.VersionSocks5, 2, protocol.MethodNoAuth, protocol.MethodUserPassAuth})
	up, err := protocol.NewUserPassRequest(protocol.UserPassAuthVersion, []byte("foo"), []byte("bar"))
	require.NoError(t, err)
	req.Write(up.Bytes())
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandConnect, DstAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: backendAddr.Port, AddrType: protocol.ATYPIPv4}}
	req.Write(head.Bytes())
	req.WriteString("ping")
	_, _ = conn.Write(req.Bytes())

	// method
	m := make([]byte, 2)
	_, err = io.ReadFull(conn, m)
	require.NoError(t, err)
	// auth
	a := make([]byte, 2)
	_, err = io.ReadFull(conn, a)
	require.NoError(t, err)
	// reply
	rep, err := protocol.ParseReply(conn)
	require.NoError(t, err)
	assert.Equal(t, protocol.RepSuccess, rep.Response)
	// optional payload from custom handler; we just ensure connection stays readable
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = conn.Read(make([]byte, 1))
	_ = conn.SetReadDeadline(time.Time{})
}
