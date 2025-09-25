package socks5_test

import (
	socks5 "go-s5"
	"go-s5/auth"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	xproxy "golang.org/x/net/proxy"
)

func Test_SocksWithProxy(t *testing.T) {
	// backend
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func(l net.Listener) {
		_ = l.Close()
	}(l)
	go func() {
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
	backend := l.Addr().(*net.TCPAddr)

	cator := auth.UserPassAuthenticator{Credentials: auth.StaticCredentials{"foo": "bar"}}
	listen, stop := startSocks5(t,
		socks5.WithAuthMethods([]auth.Authenticator{cator}),
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)
	defer stop()

	dialer, err := xproxy.SOCKS5("tcp", listen, &xproxy.Auth{User: "foo", Password: "bar"}, xproxy.Direct)
	require.NoError(t, err)
	conn, err := dialer.Dial("tcp", backend.String())
	require.NoError(t, err)
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	_, _ = conn.Write([]byte("ping"))
	out := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err = io.ReadFull(conn, out)
	_ = conn.SetReadDeadline(time.Time{})
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), out)
}
