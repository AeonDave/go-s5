package socks5_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	client "github.com/AeonDave/go-s5/client"
	handler "github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/protocol"
	server "github.com/AeonDave/go-s5/server"

	"github.com/stretchr/testify/require"
)

func TestMiddlewareChainExecute_OrderAndShortCircuit(t *testing.T) {
	var order []string
	mw := func(name string, fail bool) handler.Middleware {
		return func(ctx context.Context, w io.Writer, req *handler.Request) error {
			order = append(order, name)
			if fail {
				return errors.New("stop: " + name)
			}
			return nil
		}
	}
	last := func(ctx context.Context, w io.Writer, req *handler.Request) error {
		order = append(order, "last")
		return nil
	}

	chain := handler.MiddlewareChain{mw("a", false), mw("b", false)}
	err := chain.Execute(context.Background(), &bytes.Buffer{}, &handler.Request{}, last)
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b", "last"}, order)

	order = nil
	chain = handler.MiddlewareChain{mw("a", false), mw("boom", true), mw("never", false)}
	err = chain.Execute(context.Background(), &bytes.Buffer{}, &handler.Request{}, last)
	require.Error(t, err)
	require.Equal(t, []string{"a", "boom"}, order)
}

// End-to-end: per-command middlewares run before the default CONNECT handler.
func TestServerConnectMiddleware(t *testing.T) {
	backend, stopBackend := startTCPBackend(t)
	defer stopBackend()

	var calls int32
	mw := func(ctx context.Context, w io.Writer, req *handler.Request) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}

	listen, stop := startSocks5(t, server.WithConnectMiddleware(mw))
	defer stop()

	conn, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	cli := client.New(client.WithHandshakeTimeout(time.Second), client.WithIOTimeout(2*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = cli.Handshake(ctx, conn, nil)
	require.NoError(t, err)

	dst := protocol.AddrSpec{IP: backend.IP, Port: backend.Port, AddrType: protocol.ATYPIPv4}
	_, err = cli.Connect(ctx, conn, dst)
	require.NoError(t, err)
	require.Equal(t, int32(1), atomic.LoadInt32(&calls))
}

// A middleware error must abort the request before the handler runs.
func TestServerConnectMiddleware_ErrorAborts(t *testing.T) {
	var handled int32
	mw := func(ctx context.Context, w io.Writer, req *handler.Request) error {
		_ = server.SendReply(w, protocol.RepServerFailure, nil)
		return errors.New("denied by middleware")
	}

	listen, stop := startSocks5(t,
		server.WithConnectMiddleware(mw),
		server.WithConnectHandle(func(ctx context.Context, w io.Writer, req *handler.Request) error {
			atomic.AddInt32(&handled, 1)
			return nil
		}),
	)
	defer stop()

	conn, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	cli := client.New(client.WithHandshakeTimeout(time.Second), client.WithIOTimeout(2*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = cli.Handshake(ctx, conn, nil)
	require.NoError(t, err)

	dst := protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 1, AddrType: protocol.ATYPIPv4}
	_, err = cli.Connect(ctx, conn, dst)
	require.Error(t, err)
	require.Equal(t, int32(0), atomic.LoadInt32(&handled))
}
