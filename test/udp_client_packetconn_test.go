package socks5_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	client "github.com/AeonDave/go-s5/client"
	server "github.com/AeonDave/go-s5/server"

	"github.com/stretchr/testify/require"
)

func TestClientUDPAssociationPacketConn(t *testing.T) {
	echoAddr, stopEcho := startUDPEcho(t)
	defer stopEcho()

	socksAddr, stopS := startSocksServer(t,
		server.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			if strings.HasPrefix(network, "udp") {
				return d.DialContext(ctx, network, echoAddr)
			}
			return d.DialContext(ctx, network, addr)
		}),
	)
	defer stopS()

	conn, err := net.Dial("tcp", socksAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	cli := client.New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	_, err = cli.Handshake(ctx, conn, nil)
	require.NoError(t, err)

	assoc, _, err := cli.UDPAssociate(ctx, conn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = assoc.Close() })

	// Extract relay details and verify they are immutable copies.
	relayCopy := assoc.RelayAddress()
	require.NotNil(t, relayCopy)
	relayCopy.Port++
	require.NotEqual(t, relayCopy.Port, assoc.RelayAddr.Port)

	// Compose a long FQDN to exercise maximum header overhead handling.
	const repeatLen = 60
	longHost := strings.Repeat("a", repeatLen) + ".example.com"
	_, echoPort, err := net.SplitHostPort(echoAddr)
	require.NoError(t, err)

	payload := []byte("ping-one")
	target := fmt.Sprintf("%s:%s", longHost, echoPort)

	_, err = assoc.WriteToAddr(target, payload)
	require.NoError(t, err)

	buf := make([]byte, 256)
	n, dst, _, err := assoc.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, payload, buf[:n])
	require.Equal(t, longHost, dst.FQDN)

	// The PacketConn wrapper should accept both client.UDPAddr and *net.UDPAddr.
	pc := assoc.PacketConn()
	udpAddr, err := client.ParseUDPAddr(target)
	require.NoError(t, err)

	payload2 := []byte("ping-two")
	_, err = pc.WriteTo(payload2, udpAddr)
	require.NoError(t, err)

	buf2 := make([]byte, 256)
	n2, addr, err := pc.ReadFrom(buf2)
	require.NoError(t, err)
	require.Equal(t, payload2, buf2[:n2])

	sockAddr, ok := addr.(client.UDPAddr)
	require.True(t, ok)
	require.Equal(t, longHost, sockAddr.AddrSpec.FQDN)

	// Write using *net.UDPAddr
	hostIP := net.ParseIP("127.0.0.1")
	require.NotNil(t, hostIP)

	payload3 := []byte("ping-three")
	_, err = pc.WriteTo(payload3, &net.UDPAddr{IP: hostIP, Port: udpAddr.AddrSpec.Port})
	require.NoError(t, err)

	buf3 := make([]byte, 256)
	n3, addr3, err := pc.ReadFrom(buf3)
	require.NoError(t, err)
	require.Equal(t, payload3, buf3[:n3])

	sockAddr3, ok := addr3.(client.UDPAddr)
	require.True(t, ok)
	require.Equal(t, hostIP.String(), sockAddr3.AddrSpec.IP.String())
}
