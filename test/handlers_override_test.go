package socks5_test

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"os"
	"testing"

	socks5_handler "github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/internal/protocol"
	server "github.com/AeonDave/go-s5/server"

	"github.com/stretchr/testify/require"
)

// Verify custom Bind handler is invoked and short-circuits default behavior.
func TestBind_CustomHandler_OverridesDefault(t *testing.T) {
	listen, stop := startSocks5(t,
		server.WithLogger(server.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		server.WithBindHandle(func(_ context.Context, w io.Writer, _ *socks5_handler.Request) error {
			// Just send a success reply with dummy addr
			rsp := protocol.Reply{Version: protocol.VersionSocks5, Response: protocol.RepSuccess,
				BndAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 0, AddrType: protocol.ATYPIPv4}}
			_, err := w.Write(rsp.Bytes())
			return err
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

	// BIND request
	req := bytes.NewBuffer(nil)
	req.Write((protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandBind,
		DstAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 0, AddrType: protocol.ATYPIPv4}}).Bytes())
	_, _ = c.Write(req.Bytes())

	rep, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepSuccess), rep.Response)
}

// Verify custom Associate handler is invoked and short-circuits default behavior.
func TestAssociate_CustomHandler_OverridesDefault(t *testing.T) {
	listen, stop := startSocks5(t,
		server.WithLogger(server.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		server.WithAssociateHandle(func(_ context.Context, w io.Writer, _ *socks5_handler.Request) error {
			rsp := protocol.Reply{Version: protocol.VersionSocks5, Response: protocol.RepSuccess,
				BndAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 0, AddrType: protocol.ATYPIPv4}}
			_, err := w.Write(rsp.Bytes())
			return err
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

	// ASSOCIATE request
	req := bytes.NewBuffer(nil)
	req.Write((protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandAssociate,
		DstAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 0, AddrType: protocol.ATYPIPv4}}).Bytes())
	_, _ = c.Write(req.Bytes())

	rep, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepSuccess), rep.Response)
}
