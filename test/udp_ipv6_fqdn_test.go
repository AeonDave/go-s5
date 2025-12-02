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

// Verifies that UDP ASSOCIATE forwards FQDN datagrams to IPv6 destinations even when the client
// is connected over IPv4. The server must not force IPv4 when dialing FQDN targets, otherwise
// IPv6-only hosts become unreachable.
func TestUDP_FQDNTarget_IPv6Only(t *testing.T) {
	backend, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	require.NoError(t, err)
	defer backend.Close()

	backendAddr := backend.LocalAddr().(*net.UDPAddr)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := backend.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n > 0 {
				_, _ = backend.WriteToUDP([]byte("pong"), addr)
			}
		}
	}()

	listen, stop := startSocks5(t,
		server.WithDialAndRequest(func(ctx context.Context, network, addr string, _ *handler.Request) (net.Conn, error) {
			if network == "udp4" {
				return nil, fmt.Errorf("unexpected ipv4 network for fqdn: %s", addr)
			}
			return net.DialUDP("udp6", nil, backendAddr)
		}),
	)
	defer stop()

	ctrl, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer ctrl.Close()

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

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer client.Close()

	// Craft FQDN datagram targeting the IPv6 backend via its port.
	portBytes := []byte{byte(backendAddr.Port >> 8), byte(backendAddr.Port)}
	msg := []byte{0, 0, 0, protocol.ATYPDomain, byte(len("ipv6.test"))}
	msg = append(msg, []byte("ipv6.test")...)
	msg = append(msg, portBytes...)
	msg = append(msg, []byte("ping")...)
	_, _ = client.WriteTo(msg, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: rep.BndAddr.Port})

	buf := make([]byte, 1024)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := client.ReadFrom(buf)
	_ = client.SetReadDeadline(time.Time{})
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), buf[n-4:n])
}
