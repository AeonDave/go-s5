package socks5_test

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"
	"testing"

	socks5 "github.com/AeonDave/go-s5"
	socks5_handler "github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/internal/protocol"

	"github.com/stretchr/testify/require"
)

// Verifies dial precedence: WithDialAndRequest > WithDial > WithDialer
func TestCONNECT_Dial_Precedence(t *testing.T) {
	backend, stopBackend := startTCPBackend(t)
	defer stopBackend()

	var dialCount int32
	var dialReqCount int32

	listen, stop := startSocks5(t,
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		// Should NOT be used when WithDialAndRequest is present
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			atomic.AddInt32(&dialCount, 1)
			// If invoked, try dialing backend too to avoid masking failure
			return net.Dial(network, backend.String())
		}),
		// Must take precedence
		socks5.WithDialAndRequest(func(ctx context.Context, network, _ string, _ *socks5_handler.Request) (net.Conn, error) {
			atomic.AddInt32(&dialReqCount, 1)
			return net.Dial(network, backend.String())
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

	// CONNECT to backend
	req := bytes.NewBuffer(nil)
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandConnect,
		DstAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: backend.Port, AddrType: protocol.ATYPIPv4}}
	req.Write(head.Bytes())
	req.WriteString("ping")
	_, _ = c.Write(req.Bytes())

	rep, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepSuccess), rep.Response)

	// Read proxied payload
	out := make([]byte, 4)
	_, err = io.ReadFull(c, out)
	require.NoError(t, err)

	// Assert precedence
	require.Equal(t, int32(1), atomic.LoadInt32(&dialReqCount))
	require.Equal(t, int32(0), atomic.LoadInt32(&dialCount))
}
