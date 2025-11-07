package socks5_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	socks5_handler "github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/internal/protocol"
	server "github.com/AeonDave/go-s5/server"

	"github.com/stretchr/testify/require"
)

type ctxKey string

func dialAndExchange(t *testing.T, addr string, target *net.TCPAddr) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_, err = conn.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	require.NoError(t, err)
	reply := make([]byte, 2)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)

	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandConnect,
		DstAddr: protocol.AddrSpec{IP: target.IP, Port: target.Port, AddrType: protocol.ATYPIPv4}}
	buf := bytes.NewBuffer(nil)
	buf.Write(head.Bytes())
	buf.WriteString("ping")
	_, err = conn.Write(buf.Bytes())
	require.NoError(t, err)

	rep, err := protocol.ParseReply(conn)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepSuccess), rep.Response)

	payload := make([]byte, 4)
	_, err = io.ReadFull(conn, payload)
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), payload)
}

func TestConnContextAndMetadataPropagation(t *testing.T) {
	backend, stopBackend := startTCPBackend(t)
	defer stopBackend()

	ctxKeyID := ctxKey("session")
	ctxCh := make(chan string, 1)
	metaCh := make(chan string, 1)

	listen, stop := startSocks5(t,
		server.WithConnContext(func(ctx context.Context, conn net.Conn) context.Context {
			return context.WithValue(ctx, ctxKeyID, "ctx-"+conn.RemoteAddr().String())
		}),
		server.WithConnMetadata(func(conn net.Conn) map[string]string {
			return map[string]string{"session": "meta-" + conn.RemoteAddr().String()}
		}),
		server.WithDialAndRequest(func(ctx context.Context, network, _ string, req *socks5_handler.Request) (net.Conn, error) {
			if v, ok := ctx.Value(ctxKeyID).(string); ok {
				ctxCh <- v
			}
			if req.Metadata != nil {
				metaCh <- req.Metadata["session"]
			}
			return net.Dial(network, backend.String())
		}),
	)
	defer stop()

	dialAndExchange(t, listen, backend)

	select {
	case v := <-ctxCh:
		require.Contains(t, v, "ctx-")
	case <-time.After(time.Second):
		t.Fatal("context value not observed")
	}

	select {
	case v := <-metaCh:
		require.Contains(t, v, "meta-")
	case <-time.After(time.Second):
		t.Fatal("metadata value not observed")
	}
}

func TestServeContextCancellationPropagates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handlerDone := make(chan struct{}, 1)
	srv := server.New(
		server.WithConnectHandle(func(ctx context.Context, w io.Writer, _ *socks5_handler.Request) error {
			select {
			case <-ctx.Done():
				handlerDone <- struct{}{}
				return ctx.Err()
			case <-time.After(time.Second):
				t.Fatalf("context was not canceled")
				// t.Fatalf will terminate the test, but we need to return to satisfy the function signature
				return nil
			}
		}),
	)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ServeContext(ctx, ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	_, err = conn.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	require.NoError(t, err)
	reply := make([]byte, 2)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)

	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandConnect,
		DstAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 0, AddrType: protocol.ATYPIPv4}}
	_, err = conn.Write(head.Bytes())
	require.NoError(t, err)

	cancel()

	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("handler did not observe cancellation")
	}

	select {
	case err := <-serveErr:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("server did not stop after cancellation")
	}
}
