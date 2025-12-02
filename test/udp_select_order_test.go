package socks5_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	handler "github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/internal/protocol"
	server "github.com/AeonDave/go-s5/server"
	"github.com/stretchr/testify/require"
)

// startSocks5On starts a SOCKS5 server listening on the given TCP address (e.g. "127.0.0.1:0" or "[::1]:0").
func startSocks5On(t *testing.T, laddr string, opts ...server.Option) (listen string, stop func()) {
	t.Helper()
	srv := server.New(opts...)
	ln, err := net.Listen("tcp", laddr)
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ln)
	}()
	// small delay to ensure Serve has started
	time.Sleep(10 * time.Millisecond)
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }
}

// Ensure UDP ASSOCIATE prefers udp4 when the client UDP source is IPv4, and falls back to udp6.
func TestUDP_FQDN_FallbackOrder_IPv4Client(t *testing.T) {
	var attempts []string
	var pipeServer net.Conn
	t.Cleanup(func() {
		if pipeServer != nil {
			_ = pipeServer.Close()
		}
	})

	listen, stop := startSocks5(t,
		server.WithDialAndRequest(func(ctx context.Context, network, addr string, _ *handler.Request) (net.Conn, error) {
			attempts = append(attempts, network)
			// Fail first attempt to force fallback
			if len(attempts) == 1 {
				return nil, fmt.Errorf("fail first attempt")
			}
			// Succeed with a pipe that drains writes
			client, srv := net.Pipe()
			pipeServer = srv
			go func() {
				_, _ = io.Copy(io.Discard, srv)
			}() // drain server side
			return client, nil
		}),
	)
	defer stop()

	// Control connection over IPv4
	ctrl, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(ctrl net.Conn) {
		_ = ctrl.Close()
	}(ctrl)

	// Negotiate NoAuth and request UDP ASSOCIATE
	req := bytes.NewBuffer(nil)
	req.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	_, _ = ctrl.Write(req.Bytes())
	method := make([]byte, 2)
	_, err = io.ReadFull(ctrl, method)
	require.NoError(t, err)

	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandAssociate,
		DstAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 0, AddrType: protocol.ATYPIPv4}}
	_, _ = ctrl.Write(head.Bytes())
	rep, err := protocol.ParseReply(ctrl)
	require.NoError(t, err)

	// IPv4 UDP client
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer func(client *net.UDPConn) {
		_ = client.Close()
	}(client)

	// Send FQDN datagram to trigger dial attempts
	portBytes := []byte{0x14, 0xE7} // 5351 arbitrary
	msg := []byte{0, 0, 0, protocol.ATYPDomain, byte(len("example.test"))}
	msg = append(msg, []byte("example.test")...)
	msg = append(msg, portBytes...)
	msg = append(msg, []byte("ping")...)
	_, _ = client.WriteTo(msg, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: rep.BndAddr.Port})

	require.Eventually(t, func() bool { return len(attempts) >= 2 }, 500*time.Millisecond, 10*time.Millisecond, "expected at least two dial attempts")
	require.Equal(t, []string{"udp4", "udp6"}, attempts[:2])
}

// Ensure UDP ASSOCIATE prefers udp6 when the client UDP source is IPv6, and falls back to udp4.
func TestUDP_FQDN_FallbackOrder_IPv6Client(t *testing.T) {
	// If IPv6 UDP isn't available, skip
	udp6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Skipf("IPv6 UDP not available: %v", err)
	}
	_ = udp6.Close()

	var attempts []string
	var pipeServer net.Conn
	t.Cleanup(func() {
		if pipeServer != nil {
			_ = pipeServer.Close()
		}
	})

	// Start server on IPv6 loopback so UDP bind will be IPv6
	listen, stop := startSocks5On(t, "[::1]:0",
		server.WithDialAndRequest(func(ctx context.Context, network, addr string, _ *handler.Request) (net.Conn, error) {
			attempts = append(attempts, network)
			if len(attempts) == 1 {
				return nil, fmt.Errorf("fail first attempt")
			}
			client, srv := net.Pipe()
			pipeServer = srv
			go func() {
				_, _ = io.Copy(io.Discard, srv)
			}()
			return client, nil
		}),
	)
	defer stop()

	// Control connection over IPv6
	ctrl, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(ctrl net.Conn) {
		_ = ctrl.Close()
	}(ctrl)

	// Negotiate NoAuth and request UDP ASSOCIATE
	req := bytes.NewBuffer(nil)
	req.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	_, _ = ctrl.Write(req.Bytes())
	method := make([]byte, 2)
	_, err = io.ReadFull(ctrl, method)
	require.NoError(t, err)

	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandAssociate,
		DstAddr: protocol.AddrSpec{IP: net.IPv6loopback, Port: 0, AddrType: protocol.ATYPIPv6}}
	_, _ = ctrl.Write(head.Bytes())
	rep, err := protocol.ParseReply(ctrl)
	require.NoError(t, err)

	// IPv6 UDP client
	client, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	require.NoError(t, err)
	defer func(client *net.UDPConn) {
		_ = client.Close()
	}(client)

	// Send FQDN datagram to trigger dial attempts
	portBytes := []byte{0x14, 0xE7} // 5351 arbitrary
	msg := []byte{0, 0, 0, protocol.ATYPDomain, byte(len("example.test"))}
	msg = append(msg, []byte("example.test")...)
	msg = append(msg, portBytes...)
	msg = append(msg, []byte("ping")...)
	_, _ = client.WriteTo(msg, &net.UDPAddr{IP: net.IPv6loopback, Port: rep.BndAddr.Port})

	require.Eventually(t, func() bool { return len(attempts) >= 2 }, 500*time.Millisecond, 10*time.Millisecond, "expected at least two dial attempts")
	require.Equal(t, []string{"udp6", "udp4"}, attempts[:2])
}
