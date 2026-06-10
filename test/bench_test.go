package socks5_test

// Reproducible benchmarks for the README performance tables:
//
//	go test -bench . -benchmem -run xxx ./test/
//
// TCP relay throughput is reported as MB/s (b.SetBytes); the UDP benchmark
// reports one full proxied round trip per op.

import (
	"context"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	client "github.com/AeonDave/go-s5/client"
	"github.com/AeonDave/go-s5/protocol"
	server "github.com/AeonDave/go-s5/server"
)

func benchServer(b *testing.B) (addr string, stop func()) {
	b.Helper()
	srv := server.New()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(ln) }()
	return ln.Addr().String(), func() { _ = srv.Close(); <-done }
}

func benchConnect(b *testing.B, socksAddr, destAddr string) net.Conn {
	b.Helper()
	conn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		b.Fatal(err)
	}
	cli := client.New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err = cli.Handshake(ctx, conn, nil); err != nil {
		b.Fatal(err)
	}
	dst, err := protocol.ParseAddrSpec(destAddr)
	if err != nil {
		b.Fatal(err)
	}
	if _, err = cli.Connect(ctx, conn, dst); err != nil {
		b.Fatal(err)
	}
	return conn
}

// BenchmarkTCPRelay measures CONNECT tunnel throughput: 64 KiB writes against
// a discarding backend. The MB/s figure is the single-stream relay rate.
func BenchmarkTCPRelay(b *testing.B) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = backend.Close() }()
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(io.Discard, c); _ = c.Close() }(c)
		}
	}()

	socksAddr, stop := benchServer(b)
	defer stop()
	conn := benchConnect(b, socksAddr, backend.Addr().String())
	defer func() { _ = conn.Close() }()

	chunk := make([]byte, 64<<10)
	b.SetBytes(int64(len(chunk)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := conn.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkTCPRelayParallel measures aggregate relay throughput with one
// tunnel per CPU writing concurrently — how the server scales under
// many simultaneous streams.
func BenchmarkTCPRelayParallel(b *testing.B) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = backend.Close() }()
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(io.Discard, c); _ = c.Close() }(c)
		}
	}()

	socksAddr, stop := benchServer(b)
	defer stop()

	workers := runtime.GOMAXPROCS(0)
	conns := make(chan net.Conn, workers)
	for range workers {
		conns <- benchConnect(b, socksAddr, backend.Addr().String())
	}
	defer func() {
		close(conns)
		for c := range conns {
			_ = c.Close()
		}
	}()

	chunk := make([]byte, 64<<10)
	b.SetBytes(int64(len(chunk)))
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		conn := <-conns
		defer func() { conns <- conn }()
		for pb.Next() {
			if _, err := conn.Write(chunk); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// BenchmarkUDPRelayRoundTrip measures a full proxied UDP round trip: client ->
// relay -> echo backend -> relay -> client, with a 256-byte payload.
func BenchmarkUDPRelayRoundTrip(b *testing.B) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatal(err)
	}
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

	socksAddr, stop := benchServer(b)
	defer stop()

	ctrl, err := net.Dial("tcp", socksAddr)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = ctrl.Close() }()
	cli := client.New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err = cli.Handshake(ctx, ctrl, nil); err != nil {
		b.Fatal(err)
	}
	assoc, _, err := cli.UDPAssociate(ctx, ctrl)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = assoc.Close() }()

	dest, err := protocol.ParseAddrSpec(echo.LocalAddr().String())
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 256)
	buf := make([]byte, 2048)

	b.ReportAllocs()
	for b.Loop() {
		if _, err := assoc.WriteTo(dest, payload); err != nil {
			b.Fatal(err)
		}
		if _, _, _, err := assoc.ReadFrom(buf); err != nil {
			b.Fatal(err)
		}
	}
}
