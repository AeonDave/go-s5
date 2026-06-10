package socks5_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	client "github.com/AeonDave/go-s5/client"
	handler "github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/linkquality"
	"github.com/AeonDave/go-s5/protocol"
	server "github.com/AeonDave/go-s5/server"

	"github.com/stretchr/testify/require"
)

// selfSignedTLS generates an in-memory self-signed certificate for 127.0.0.1.
func selfSignedTLS(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "go-s5-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// freeLocalPort reserves a port by listening and closing immediately.
func freeLocalPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

func handshakeNoAuth(t *testing.T, conn net.Conn) {
	t.Helper()
	cli := client.New(client.WithHandshakeTimeout(2 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := cli.Handshake(ctx, conn, nil)
	require.NoError(t, err)
}

func TestListenAndServe(t *testing.T) {
	addr := freeLocalPort(t)
	srv := server.New()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe("tcp", addr) }()

	var conn net.Conn
	var err error
	require.Eventually(t, func() bool {
		conn, err = net.Dial("tcp", addr)
		return err == nil
	}, 2*time.Second, 20*time.Millisecond)

	handshakeNoAuth(t, conn)
	_ = conn.Close()

	// Graceful stop: ListenAndServe must return ErrServerClosed.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	require.NoError(t, srv.Shutdown(ctx))
	select {
	case err := <-serveErr:
		require.ErrorIs(t, err, server.ErrServerClosed)
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe did not return after Shutdown")
	}
}

func TestListenAndServeTLS(t *testing.T) {
	addr := freeLocalPort(t)
	cert := selfSignedTLS(t)
	srv := server.New()
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.ListenAndServeTLS("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}})
	}()

	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	var conn net.Conn
	var err error
	require.Eventually(t, func() bool {
		conn, err = tls.Dial("tcp", addr, tlsCfg)
		return err == nil
	}, 2*time.Second, 20*time.Millisecond)

	handshakeNoAuth(t, conn)
	_ = conn.Close()

	require.NoError(t, srv.Close())
	select {
	case err := <-serveErr:
		require.ErrorIs(t, err, server.ErrServerClosed)
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServeTLS did not return after Close")
	}
}

// Shutdown must wait for in-flight connections and reject new ones.
func TestShutdownGraceful(t *testing.T) {
	backend, stopBackend := startTCPBackend(t)
	defer stopBackend()

	srv := server.New()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	// Open a connection and complete handshake+CONNECT so it counts as active.
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	handshakeNoAuth(t, conn)
	cli := client.New(client.WithIOTimeout(2 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	dst := protocol.AddrSpec{IP: backend.IP, Port: backend.Port, AddrType: protocol.ATYPIPv4}
	_, err = cli.Connect(ctx, conn, dst)
	require.NoError(t, err)

	// Shutdown with a short deadline: the proxy conn is still active, so it
	// must time out with the connection running.
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer shortCancel()
	require.ErrorIs(t, srv.Shutdown(shortCtx), context.DeadlineExceeded)

	// The active tunnel must still work after the failed graceful window.
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), buf)

	// New connections must be refused (listener closed).
	_, err = net.Dial("tcp", ln.Addr().String())
	require.Error(t, err)

	// Close the client side; a second Shutdown now drains cleanly.
	_ = conn.Close()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	require.NoError(t, srv.Shutdown(ctx2))

	select {
	case err := <-serveErr:
		require.ErrorIs(t, err, server.ErrServerClosed)
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}

	// Serving again on a closed server must fail fast.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln2.Close() }()
	require.ErrorIs(t, srv.Serve(ln2), server.ErrServerClosed)
}

// Close must tear down active connections immediately.
func TestCloseImmediate(t *testing.T) {
	backend, stopBackend := startTCPBackend(t)
	defer stopBackend()

	srv := server.New()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	handshakeNoAuth(t, conn)
	cli := client.New(client.WithIOTimeout(2 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	dst := protocol.AddrSpec{IP: backend.IP, Port: backend.Port, AddrType: protocol.ATYPIPv4}
	_, err = cli.Connect(ctx, conn, dst)
	require.NoError(t, err)

	require.NoError(t, srv.Close())

	select {
	case err := <-serveErr:
		require.ErrorIs(t, err, server.ErrServerClosed)
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Close")
	}

	// The proxied connection must observe the teardown shortly.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	require.Error(t, err)
}

func TestServeConn(t *testing.T) {
	backend, stopBackend := startTCPBackend(t)
	defer stopBackend()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	srv := server.New()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = srv.ServeConn(c)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	handshakeNoAuth(t, conn)

	cli := client.New(client.WithIOTimeout(2 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	dst := protocol.AddrSpec{IP: backend.IP, Port: backend.Port, AddrType: protocol.ATYPIPv4}
	_, err = cli.Connect(ctx, conn, dst)
	require.NoError(t, err)

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), buf)
}

type ctxBaseKey struct{}

// One e2e covering WithBaseContext, WithConnState, WithLinkQuality, and the
// LinkQualityTracker accessor together.
func TestServerLifecycleOptions(t *testing.T) {
	backend, stopBackend := startTCPBackend(t)
	defer stopBackend()

	states := make(chan server.ConnState, 8)
	baseSeen := make(chan string, 1)
	tracker := linkquality.NewTracker(linkquality.Metadata{Kind: linkquality.EndpointTCP})

	srv := server.New(
		server.WithBaseContext(func(net.Listener) context.Context {
			return context.WithValue(context.Background(), ctxBaseKey{}, "from-base")
		}),
		server.WithConnState(func(_ net.Conn, st server.ConnState) {
			states <- st
		}),
		server.WithLinkQuality(tracker),
		server.WithDialAndRequest(func(ctx context.Context, network, addr string, _ *handler.Request) (net.Conn, error) {
			if v, ok := ctx.Value(ctxBaseKey{}).(string); ok {
				select {
				case baseSeen <- v:
				default:
				}
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}),
	)
	require.Same(t, tracker, srv.LinkQualityTracker())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close(); <-done })

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)

	handshakeNoAuth(t, conn)
	cli := client.New(client.WithIOTimeout(2 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	dst := protocol.AddrSpec{IP: backend.IP, Port: backend.Port, AddrType: protocol.ATYPIPv4}
	_, err = cli.Connect(ctx, conn, dst)
	require.NoError(t, err)

	select {
	case v := <-baseSeen:
		require.Equal(t, "from-base", v)
	case <-time.After(2 * time.Second):
		t.Fatal("base context value not propagated to dialer")
	}

	// Outbound dial must have been recorded by the tracker.
	require.Eventually(t, func() bool {
		return tracker.ConnectionInfo().Probes >= 1
	}, 2*time.Second, 20*time.Millisecond)

	_ = conn.Close()

	// Expect the full lifecycle: New -> Active -> Closed.
	var seen []server.ConnState
	deadline := time.After(3 * time.Second)
	for len(seen) < 3 {
		select {
		case st := <-states:
			seen = append(seen, st)
		case <-deadline:
			t.Fatalf("incomplete conn state transitions: %v", seen)
		}
	}
	require.Equal(t, []server.ConnState{server.StateNew, server.StateActive, server.StateClosed}, seen[:3])
}

// syncBuffer is a bytes.Buffer safe for concurrent writes from server goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestConnectionLoggingInfof(t *testing.T) {
	out := &syncBuffer{}
	logger := server.NewLogger(log.New(out, "", 0))

	listen, stop := startSocks5(t,
		server.WithLogger(logger),
		server.WithConnectionLogging(true),
	)
	defer stop()

	conn, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	handshakeNoAuth(t, conn)
	_ = conn.Close()

	require.Eventually(t, func() bool {
		s := out.String()
		return len(s) > 0 && containsAll(s, "accepted", "closed")
	}, 3*time.Second, 50*time.Millisecond, "expected accept/close log lines, got: %q", out.String())
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !bytes.Contains([]byte(s), []byte(sub)) {
			return false
		}
	}
	return true
}
