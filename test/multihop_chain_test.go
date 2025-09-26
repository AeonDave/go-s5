package socks5_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/AeonDave/go-s5/client"
	"github.com/AeonDave/go-s5/protocol"

	"github.com/stretchr/testify/require"
)

func TestClient_DialChain_TwoHops_TCP(t *testing.T) {
	backendAddr, stopBackend := startTCPBackend(t)
	defer stopBackend()

	hop1, stop1 := startSocks5(t)
	defer stop1()
	hop2, stop2 := startSocks5(t)
	defer stop2()

	chain := []client.Hop{{Address: hop1}, {Address: hop2}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cli := client.New(client.WithHandshakeTimeout(1*time.Second), client.WithIOTimeout(2*time.Second))
	conn, err := cli.DialChain(ctx, chain, backendAddr.String(), 2*time.Second)
	require.NoError(t, err)
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
}

func TestClient_DialChain_UDPAssociate(t *testing.T) {
	// UDP echo backend
	locIP := net.ParseIP("127.0.0.1")
	upstream, err := net.ListenUDP("udp", &net.UDPAddr{IP: locIP, Port: 0})
	require.NoError(t, err)
	defer func(upstream *net.UDPConn) {
		_ = upstream.Close()
	}(upstream)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, r, err := upstream.ReadFrom(buf)
			if err != nil {
				return
			}
			if n > 0 {
				_, _ = upstream.WriteTo([]byte("pong"), r)
			}
		}
	}()
	udpPort := upstream.LocalAddr().(*net.UDPAddr).Port

	hop1, stop1 := startSocks5(t)
	defer stop1()
	hop2, stop2 := startSocks5(t)
	defer stop2()

	chain := []client.Hop{{Address: hop1}, {Address: hop2}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Build chain TCP control connection to last hop
	// Stop at last hop (finalTarget="") so UDPAssociate talks to SOCKS, not a tunneled endpoint
	cli := client.New(client.WithHandshakeTimeout(1*time.Second), client.WithIOTimeout(2*time.Second))
	conn, err := cli.DialChain(ctx, chain, "", 2*time.Second)
	require.NoError(t, err)
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	cli2 := client.New(client.WithHandshakeTimeout(1*time.Second), client.WithIOTimeout(2*time.Second))
	assoc, rep, err := cli2.UDPAssociate(ctx, conn)
	require.NoError(t, err)
	require.NotZero(t, rep.BndAddr.Port)
	defer func(assoc *client.UDPAssociation) {
		_ = assoc.Close()
	}(assoc)

	// Send datagram via relay to upstream
	dst := protocol.AddrSpec{IP: locIP, Port: udpPort, AddrType: protocol.ATYPIPv4}
	_, err = assoc.WriteTo(dst, []byte("ping"))
	require.NoError(t, err)

	buf := make([]byte, 1024)
	_ = assoc.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, _, err := assoc.ReadFrom(buf)
	require.NoError(t, err)
	_ = assoc.Conn.SetReadDeadline(time.Time{})
	require.Equal(t, []byte("pong"), buf[n-4:n])
}
