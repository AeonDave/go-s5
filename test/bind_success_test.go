package socks5_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/AeonDave/go-s5/internal/protocol"
	server "github.com/AeonDave/go-s5/server"

	"github.com/stretchr/testify/require"
)

// BIND end-to-end: client requests BIND, peer connects, proxy forwards data both ways.
func TestBIND_WithPeer_Success(t *testing.T) {
	listen, stop := startSocks5(t,
		server.WithLogger(server.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		server.WithBindPeerCheckIPOnly(true), // accept peer by IP (port wildcard)
	)
	defer stop()

	// control connection
	client, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(client net.Conn) {
		_ = client.Close()
	}(client)

	// handshake (NoAuth)
	_, _ = client.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	sel := make([]byte, 2)
	_, err = io.ReadFull(client, sel)
	require.NoError(t, err)

	// request BIND to accept from 127.0.0.1 (port wildcard)
	req := bytes.NewBuffer(nil)
	req.Write((protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandBind,
		DstAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 0, AddrType: protocol.ATYPIPv4}}).Bytes())
	_, _ = client.Write(req.Bytes())

	// first reply: bind address to connect to
	rep1, err := protocol.ParseReply(client)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepSuccess), rep1.Response)
	bindAddr := fmt.Sprintf("%s:%d", rep1.BndAddr.IP.String(), rep1.BndAddr.Port)

	// peer connects to bind address
	peer, err := net.Dial("tcp", bindAddr)
	require.NoError(t, err)
	defer func(peer net.Conn) {
		_ = peer.Close()
	}(peer)

	// second reply should indicate connected peer
	rep2, err := protocol.ParseReply(client)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepSuccess), rep2.Response)

	// now proxy is active: client -> peer
	_, _ = client.Write([]byte("ping"))
	buf := make([]byte, 4)
	_, err = io.ReadFull(peer, buf)
	require.NoError(t, err)
	require.Equal(t, []byte("ping"), buf)

	// peer -> client
	_, _ = peer.Write([]byte("pong"))
	_ = client.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, err = io.ReadFull(client, buf)
	_ = client.SetReadDeadline(time.Time{})
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), buf)
}
