package socks5_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	client "github.com/AeonDave/go-s5/client"
	"github.com/AeonDave/go-s5/protocol"
	server "github.com/AeonDave/go-s5/server"

	"github.com/stretchr/testify/require"
)

// startDiscardBackend returns a TCP listener whose accepted connections are
// drained and kept open until the listener closes.
func startDiscardBackend(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(io.Discard, c); _ = c.Close() }(c)
		}
	}()
	return ln
}

func startServer(t *testing.T, opts ...server.Option) string {
	t.Helper()
	srv := server.New(opts...)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// connectThrough opens a SOCKS5 tunnel to dest and returns the client conn.
func connectThrough(t *testing.T, socksAddr, dest string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", socksAddr)
	require.NoError(t, err)
	cli := client.New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = cli.Handshake(ctx, conn, nil)
	require.NoError(t, err)
	dst, err := protocol.ParseAddrSpec(dest)
	require.NoError(t, err)
	_, err = cli.Connect(ctx, conn, dst)
	require.NoError(t, err)
	return conn
}

func TestSOCKS5_MaxConnections(t *testing.T) {
	backend := startDiscardBackend(t)
	metrics := &server.CounterMetrics{}
	socksAddr := startServer(t,
		server.WithMaxConnections(1),
		server.WithMetrics(metrics),
	)

	// First connection occupies the only slot.
	held := connectThrough(t, socksAddr, backend.Addr().String())
	defer func() { _ = held.Close() }()

	// Second connection must be closed before any SOCKS handshake completes.
	rejected, err := net.Dial("tcp", socksAddr)
	require.NoError(t, err)
	defer func() { _ = rejected.Close() }()
	cli := client.New()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = cli.Handshake(ctx, rejected, nil)
	require.Error(t, err, "handshake on a rejected connection must fail")

	require.Eventually(t, func() bool {
		return metrics.Snapshot().Rejected == 1
	}, 2*time.Second, 10*time.Millisecond)

	// Releasing the held connection frees the slot for new clients.
	_ = held.Close()
	require.Eventually(t, func() bool {
		c, err := net.Dial("tcp", socksAddr)
		if err != nil {
			return false
		}
		defer func() { _ = c.Close() }()
		hctx, hcancel := context.WithTimeout(context.Background(), time.Second)
		defer hcancel()
		_, err = client.New().Handshake(hctx, c, nil)
		return err == nil
	}, 3*time.Second, 50*time.Millisecond)
}

func TestSOCKS5_ConnectionRateLimit(t *testing.T) {
	metrics := &server.CounterMetrics{}
	// 0.1 conns/s sustained with a burst of 2: the 3rd immediate connection
	// from the same source must be rejected.
	socksAddr := startServer(t,
		server.WithConnectionRateLimit(0.1, 2),
		server.WithMetrics(metrics),
	)

	handshake := func() error {
		c, err := net.Dial("tcp", socksAddr)
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err = client.New().Handshake(ctx, c, nil)
		return err
	}

	require.NoError(t, handshake(), "1st connection within burst")
	require.NoError(t, handshake(), "2nd connection within burst")
	require.Error(t, handshake(), "3rd connection must be rate limited")

	require.Eventually(t, func() bool {
		return metrics.Snapshot().Rejected >= 1
	}, 2*time.Second, 10*time.Millisecond)
	require.Equal(t, int64(2), metrics.Snapshot().Accepted)
}

func TestSOCKS5_MetricsCounters(t *testing.T) {
	backend := startDiscardBackend(t)
	metrics := &server.CounterMetrics{}
	socksAddr := startServer(t, server.WithMetrics(metrics))

	conn := connectThrough(t, socksAddr, backend.Addr().String())
	payload := make([]byte, 4096)
	_, err := conn.Write(payload)
	require.NoError(t, err)
	_ = conn.Close()

	require.Eventually(t, func() bool {
		s := metrics.Snapshot()
		return s.Accepted == 1 && s.Closed == 1 && s.Requests == 1 && s.RelayedBytes >= int64(len(payload))
	}, 3*time.Second, 10*time.Millisecond, "final snapshot: %+v", metrics.Snapshot())
	require.Equal(t, int64(0), metrics.Snapshot().Rejected)
}

func TestSOCKS5_MetricsUDPRelayBytes(t *testing.T) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer func() { _ = echo.Close() }()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, peer, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(buf[:n], peer)
		}
	}()

	metrics := &server.CounterMetrics{}
	socksAddr := startServer(t, server.WithMetrics(metrics))

	ctrl, err := net.Dial("tcp", socksAddr)
	require.NoError(t, err)
	defer func() { _ = ctrl.Close() }()
	cli := client.New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = cli.Handshake(ctx, ctrl, nil)
	require.NoError(t, err)
	assoc, _, err := cli.UDPAssociate(ctx, ctrl)
	require.NoError(t, err)
	defer func() { _ = assoc.Close() }()

	dest, err := protocol.ParseAddrSpec(echo.LocalAddr().String())
	require.NoError(t, err)
	payload := make([]byte, 512)
	_, err = assoc.WriteTo(dest, payload)
	require.NoError(t, err)
	buf := make([]byte, 2048)
	n, _, _, err := assoc.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)

	// Both directions counted: client->target and target->client payloads.
	require.Eventually(t, func() bool {
		return metrics.Snapshot().RelayedBytes >= int64(2*len(payload))
	}, 3*time.Second, 10*time.Millisecond, "snapshot: %+v", metrics.Snapshot())
}

type alwaysFailResolver struct{}

func (alwaysFailResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, errors.New("resolver must not be consulted with WithDialFQDN")
}

func TestSOCKS5_DialFQDN_BypassesResolver(t *testing.T) {
	backend := startDiscardBackend(t)
	_, port, err := net.SplitHostPort(backend.Addr().String())
	require.NoError(t, err)

	// With WithDialFQDN the failing resolver is never consulted for CONNECT:
	// the hostname goes straight to net.Dialer (Happy Eyeballs path).
	socksAddr := startServer(t,
		server.WithDialFQDN(true),
		server.WithResolver(alwaysFailResolver{}),
	)
	conn := connectThrough(t, socksAddr, "localhost:"+port)
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)

	// Sanity check: without the option the same setup must fail on resolve.
	plainAddr := startServer(t, server.WithResolver(alwaysFailResolver{}))
	c, err := net.Dial("tcp", plainAddr)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cli := client.New()
	_, err = cli.Handshake(ctx, c, nil)
	require.NoError(t, err)
	dst, err := protocol.ParseAddrSpec("localhost:" + port)
	require.NoError(t, err)
	_, err = cli.Connect(ctx, c, dst)
	require.Error(t, err, "without WithDialFQDN the failing resolver must surface")
}
