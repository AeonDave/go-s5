package main

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/AeonDave/go-s5/auth"
	"github.com/AeonDave/go-s5/client"
	"github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/protocol"
	"github.com/AeonDave/go-s5/server"

	"github.com/stretchr/testify/require"
)

func startCLIBackend(t *testing.T) (addr *net.TCPAddr, stop func()) {
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
		defer func(conn net.Conn) { _ = conn.Close() }(conn)
		buf := make([]byte, 4)
		_, err = io.ReadAtLeast(conn, buf, 4)
		if err == nil {
			_, _ = conn.Write([]byte("pong"))
		}
	}()
	return l.Addr().(*net.TCPAddr), func() { _ = l.Close(); <-stopped }
}

func startCLIServer(t *testing.T, opts ...server.Option) (listen string, stop func()) {
	t.Helper()
	srv := server.New(opts...)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ln)
	}()
	time.Sleep(10 * time.Millisecond)
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }
}

type rewriteToAddr struct {
	dst protocol.AddrSpec
}

func (r rewriteToAddr) Rewrite(ctx context.Context, _ *handler.Request) (context.Context, *protocol.AddrSpec) {
	return ctx, &r.dst
}

func dialViaCLIProxy(t *testing.T, proxyAddr, dest string) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	require.NoError(t, err)
	defer func(conn net.Conn) { _ = conn.Close() }(conn)

	cli := client.New(client.WithHandshakeTimeout(1*time.Second), client.WithIOTimeout(2*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = cli.Handshake(ctx, conn, nil)
	require.NoError(t, err)

	dst, err := protocol.ParseAddrSpec(dest)
	require.NoError(t, err)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	_, err = cli.Connect(ctx2, conn, dst)
	require.NoError(t, err)

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)

	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), buf)
}

func TestServerOptionsFromConfig_UpstreamDialer(t *testing.T) {
	unreachable := "203.0.113.1:6553"

	t.Run("without_auth", func(t *testing.T) {
		backendAddr, stopBackend := startCLIBackend(t)
		defer stopBackend()
		rewrite := rewriteToAddr{dst: protocol.AddrSpec{IP: backendAddr.IP, Port: backendAddr.Port, AddrType: protocol.ATYPIPv4}}

		upstreamListen, stopUpstream := startCLIServer(t, server.WithRewriter(rewrite))
		defer stopUpstream()

		cfg := serverFlags{upstream: upstreamListen}
		opts, err := serverOptionsFromConfig(cfg)
		require.NoError(t, err)

		listen, stop := startCLIServer(t, opts...)
		defer stop()

		dialViaCLIProxy(t, listen, unreachable)
	})

	t.Run("with_auth", func(t *testing.T) {
		backendAddr, stopBackend := startCLIBackend(t)
		defer stopBackend()
		rewrite := rewriteToAddr{dst: protocol.AddrSpec{IP: backendAddr.IP, Port: backendAddr.Port, AddrType: protocol.ATYPIPv4}}

		upstreamListen, stopUpstream := startCLIServer(t,
			server.WithCredential(auth.StaticCredentials{"alice": "secret"}),
			server.WithRewriter(rewrite),
		)
		defer stopUpstream()

		cfg := serverFlags{upstream: upstreamListen, upstreamUser: "alice", upstreamPass: "secret"}
		opts, err := serverOptionsFromConfig(cfg)
		require.NoError(t, err)

		listen, stop := startCLIServer(t, opts...)
		defer stop()

		dialViaCLIProxy(t, listen, unreachable)
	})

	t.Run("missing_upstream_credentials", func(t *testing.T) {
		backendAddr, stopBackend := startCLIBackend(t)
		defer stopBackend()
		rewrite := rewriteToAddr{dst: protocol.AddrSpec{IP: backendAddr.IP, Port: backendAddr.Port, AddrType: protocol.ATYPIPv4}}

		upstreamListen, stopUpstream := startCLIServer(t,
			server.WithCredential(auth.StaticCredentials{"alice": "secret"}),
			server.WithRewriter(rewrite),
		)
		defer stopUpstream()

		cfg := serverFlags{upstream: upstreamListen}
		opts, err := serverOptionsFromConfig(cfg)
		require.NoError(t, err)

		listen, stop := startCLIServer(t, opts...)
		defer stop()

		conn, err := net.Dial("tcp", listen)
		require.NoError(t, err)
		defer func(conn net.Conn) { _ = conn.Close() }(conn)

		cli := client.New(client.WithHandshakeTimeout(1*time.Second), client.WithIOTimeout(2*time.Second))
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err = cli.Handshake(ctx, conn, nil)
		require.NoError(t, err)

		dst, err := protocol.ParseAddrSpec(unreachable)
		require.NoError(t, err)

		ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel2()
		_, err = cli.Connect(ctx2, conn, dst)
		require.Error(t, err)
	})

	t.Run("udp_associate_bypasses_upstream", func(t *testing.T) {
		backend, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		require.NoError(t, err)
		defer backend.Close()

		done := make(chan struct{})
		go func() {
			defer close(done)
			buf := make([]byte, 64)
			_ = backend.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, addr, rErr := backend.ReadFromUDP(buf)
			if rErr != nil {
				return
			}
			_, _ = backend.WriteToUDP([]byte("pong"), addr)
			_ = backend.SetReadDeadline(time.Time{})
		}()

		cfg := serverFlags{upstream: "127.0.0.1:9"}
		opts, err := serverOptionsFromConfig(cfg)
		require.NoError(t, err)

		listen, stop := startCLIServer(t, opts...)
		defer stop()

		conn, err := net.Dial("tcp", listen)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		cli := client.New(client.WithHandshakeTimeout(2*time.Second), client.WithIOTimeout(2*time.Second))
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err = cli.Handshake(ctx, conn, nil)
		require.NoError(t, err)
		t.Log("handshake complete")

		assoc, rep, err := cli.UDPAssociate(ctx, conn)
		require.NoError(t, err)
		require.Equal(t, protocol.RepSuccess, rep.Response)
		t.Cleanup(func() { _ = assoc.Close() })
		t.Log("udp associate established")

		dest := &protocol.AddrSpec{IP: backend.LocalAddr().(*net.UDPAddr).IP, Port: backend.LocalAddr().(*net.UDPAddr).Port, AddrType: protocol.ATYPIPv4}
		_, err = assoc.WriteTo(*dest, []byte("ping"))
		require.NoError(t, err)
		t.Log("datagram sent")

		buf := make([]byte, 32)
		_ = assoc.Conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := assoc.Conn.ReadFromUDP(buf)
		require.NoError(t, err)
		t.Logf("received %d bytes", n)

		dg, err := protocol.ParseDatagram(buf[:n])
		require.NoError(t, err)
		require.Equal(t, []byte("pong"), dg.Data)

		_ = assoc.Conn.SetReadDeadline(time.Time{})
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("backend did not finish")
		}
	})
}
