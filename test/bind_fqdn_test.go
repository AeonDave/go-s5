package socks5_test

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/AeonDave/go-s5/internal/protocol"
	server "github.com/AeonDave/go-s5/server"

	"github.com/stretchr/testify/require"
)

type staticResolver struct {
	ip net.IP
}

func (s staticResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	if s.ip == nil {
		return ctx, nil, nil
	}
	cp := append(net.IP(nil), s.ip...)
	return ctx, cp, nil
}

// Verifies that BIND requests using FQDN destinations are resolved and matched
// against the connecting peer IP when acting as a reverse SOCKS5 proxy.
func TestBIND_FQDNResolver_AllowsMatchingPeer(t *testing.T) {
	listen, stop := startSocks5(t,
		server.WithLogger(server.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		server.WithResolver(staticResolver{ip: net.ParseIP("127.0.0.1")}),
	)
	defer stop()

	c, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(c net.Conn) {
		_ = c.Close()
	}(c)

	// handshake: NoAuth
	_, _ = c.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	sel := make([]byte, 2)
	_, err = io.ReadFull(c, sel)
	require.NoError(t, err)

	// Issue BIND request using FQDN destination which resolves to loopback.
	req := bytes.NewBuffer(nil)
	req.Write((protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandBind,
		DstAddr: protocol.AddrSpec{FQDN: "example.com", Port: 0, AddrType: protocol.ATYPDomain}}).Bytes())
	_, _ = c.Write(req.Bytes())

	rep1, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepSuccess), rep1.Response)
	bindAddr := net.JoinHostPort(rep1.BndAddr.IP.String(), strconv.Itoa(rep1.BndAddr.Port))

	peer, err := net.Dial("tcp", bindAddr)
	require.NoError(t, err)
	defer func(peer net.Conn) {
		_ = peer.Close()
	}(peer)

	rep2, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepSuccess), rep2.Response)

	// Verify bidirectional proxying works.
	_, _ = c.Write([]byte("ping"))
	buf := make([]byte, 4)
	_, err = io.ReadFull(peer, buf)
	require.NoError(t, err)
	require.Equal(t, []byte("ping"), buf)

	_, _ = peer.Write([]byte("pong"))
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	_, err = io.ReadFull(c, buf)
	_ = c.SetReadDeadline(time.Time{})
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), buf)
}

// When the resolver returns an IP different from the connecting peer, the
// server should reject the peer and emit TTLExpired, exercising the reverse
// proxy safeguards for mismatched clients.
func TestBIND_FQDNResolver_MismatchedPeerRejected(t *testing.T) {
	listen, stop := startSocks5(t,
		server.WithLogger(server.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		server.WithResolver(staticResolver{ip: net.ParseIP("127.0.0.2")}),
		server.WithBindAcceptTimeout(150*time.Millisecond),
	)
	defer stop()

	c, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(c net.Conn) {
		_ = c.Close()
	}(c)

	// handshake: NoAuth
	_, _ = c.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	sel := make([]byte, 2)
	_, err = io.ReadFull(c, sel)
	require.NoError(t, err)

	req := bytes.NewBuffer(nil)
	req.Write((protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandBind,
		DstAddr: protocol.AddrSpec{FQDN: "example.com", Port: 0, AddrType: protocol.ATYPDomain}}).Bytes())
	_, _ = c.Write(req.Bytes())

	rep1, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepSuccess), rep1.Response)
	bindAddr := net.JoinHostPort(rep1.BndAddr.IP.String(), strconv.Itoa(rep1.BndAddr.Port))

	peer, err := net.Dial("tcp", bindAddr)
	require.NoError(t, err)
	_ = peer.Close()

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	rep2, err := protocol.ParseReply(c)
	_ = c.SetReadDeadline(time.Time{})
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepTTLExpired), rep2.Response)
}
