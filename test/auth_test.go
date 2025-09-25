package socks5_test

import (
	"bytes"
	socks5 "go-s5"
	"go-s5/auth"
	"go-s5/internal/protocol"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAuth_NoAuth(t *testing.T) {
	listen, stop := startSocks5(t,
		socks5.WithAuthMethods([]auth.Authenticator{&auth.NoAuthAuthenticator{}}),
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)
	defer stop()

	conn, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	// Offer NoAuth only
	_, _ = conn.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	require.Equal(t, []byte{protocol.VersionSocks5, protocol.MethodNoAuth}, buf)
}

func TestAuth_UserPass_Valid(t *testing.T) {
	listen, stop := startSocks5(t,
		socks5.WithAuthMethods([]auth.Authenticator{auth.UserPassAuthenticator{Credentials: auth.StaticCredentials{"foo": "bar"}}}),
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)
	defer stop()
	conn, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)
	// Offer methods + then send userpass
	req := bytes.NewBuffer(nil)
	req.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodUserPassAuth})
	up := protocol.NewUserPassRequest(protocol.UserPassAuthVersion, []byte("foo"), []byte("bar"))
	req.Write(up.Bytes())
	_, _ = conn.Write(req.Bytes())
	// method
	m := make([]byte, 2)
	_, err = io.ReadFull(conn, m)
	require.NoError(t, err)
	// auth reply
	a := make([]byte, 2)
	_, err = io.ReadFull(conn, a)
	require.NoError(t, err)
	require.Equal(t, []byte{protocol.UserPassAuthVersion, protocol.AuthSuccess}, a)
}

func TestAuth_UserPass_Invalid(t *testing.T) {
	listen, stop := startSocks5(t,
		socks5.WithAuthMethods([]auth.Authenticator{auth.UserPassAuthenticator{Credentials: auth.StaticCredentials{"foo": "bar"}}}),
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		socks5.WithHandshakeTimeout(500*time.Millisecond),
	)
	defer stop()
	conn, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)
	// Offer methods + invalid userpass
	req := bytes.NewBuffer(nil)
	req.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodUserPassAuth})
	up := protocol.NewUserPassRequest(protocol.UserPassAuthVersion, []byte("foo"), []byte("baz"))
	req.Write(up.Bytes())
	_, _ = conn.Write(req.Bytes())
	// method
	m := make([]byte, 2)
	_, err = io.ReadFull(conn, m)
	require.NoError(t, err)
	// auth reply should be failure then the server will close the conn
	a := make([]byte, 2)
	_, err = io.ReadFull(conn, a)
	require.NoError(t, err)
	require.Equal(t, []byte{protocol.UserPassAuthVersion, protocol.AuthFailure}, a)
	// subsequent read should hit EOF within timeout
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn.Read(make([]byte, 1))
	require.Error(t, err)
}

func TestAuth_NoSupported(t *testing.T) {
	// Server only supports userpass; client offers only no-auth
	listen, stop := startSocks5(t,
		socks5.WithAuthMethods([]auth.Authenticator{auth.UserPassAuthenticator{Credentials: auth.StaticCredentials{"foo": "bar"}}}),
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)
	defer stop()
	conn, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)
	_, _ = conn.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	b := make([]byte, 2)
	_, err = io.ReadFull(conn, b)
	require.NoError(t, err)
	require.Equal(t, []byte{protocol.VersionSocks5, protocol.MethodNoAcceptable}, b)
}
