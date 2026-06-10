package socks5_test

import (
	"net"
	"testing"
	"time"

	cudp "github.com/AeonDave/go-s5/client/udp"
	"github.com/AeonDave/go-s5/protocol"

	"github.com/stretchr/testify/require"
)

func newLocalUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestUDPAssociation_ConstructorErrors(t *testing.T) {
	relay := newLocalUDP(t)
	local := newLocalUDP(t)

	_, err := cudp.NewAssociation(nil, relay.LocalAddr().(*net.UDPAddr))
	require.Error(t, err)
	_, err = cudp.NewAssociation(local, nil)
	require.Error(t, err)
}

func TestUDPAssociation_AccessorsAndDeadlines(t *testing.T) {
	relay := newLocalUDP(t)
	local := newLocalUDP(t)

	assoc, err := cudp.NewAssociation(local, relay.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	t.Cleanup(func() { _ = assoc.Close() })

	require.Equal(t, local.LocalAddr().String(), assoc.LocalAddr().String())
	require.NoError(t, assoc.SetDeadline(time.Now().Add(time.Second)))
	require.NoError(t, assoc.SetReadDeadline(time.Now().Add(time.Second)))
	require.NoError(t, assoc.SetWriteDeadline(time.Now().Add(time.Second)))
	require.NoError(t, assoc.SetDeadline(time.Time{}))

	// RelayAddress returns a defensive copy.
	cp := assoc.RelayAddress()
	require.NotNil(t, cp)
	require.Equal(t, assoc.RelayAddr.String(), cp.String())
	cp.IP[0] = 9
	require.NotEqual(t, cp.IP.String(), assoc.RelayAddr.IP.String())

	// Nil receiver safety.
	var nilAssoc *cudp.Association
	require.NoError(t, nilAssoc.Close())
	require.Nil(t, nilAssoc.LocalAddr())
	require.Nil(t, nilAssoc.RelayAddress())
	require.Error(t, nilAssoc.SetDeadline(time.Time{}))
	require.Error(t, nilAssoc.SetReadDeadline(time.Time{}))
	require.Error(t, nilAssoc.SetWriteDeadline(time.Time{}))
	nilAssoc.ConfigureKeepAlive(time.Second, nil) // must not panic
}

func TestUDPAddrAndParseAddr(t *testing.T) {
	a, err := cudp.ParseAddr("example.org:443")
	require.NoError(t, err)
	require.Equal(t, "socks5+udp", a.Network())
	require.Contains(t, a.String(), "example.org")

	_, err = cudp.ParseAddr("not-an-address")
	require.Error(t, err)
}

// PacketConn roundtrip through a fake relay that echoes SOCKS5 datagrams back.
func TestUDPAssociation_PacketConnRoundtrip(t *testing.T) {
	relay := newLocalUDP(t)
	local := newLocalUDP(t)

	// Fake relay: parse the datagram, echo it back unchanged to the sender.
	go func() {
		buf := make([]byte, 2048)
		_ = relay.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, src, err := relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		_, _ = relay.WriteToUDP(buf[:n], src)
	}()

	assoc, err := cudp.NewAssociation(local, relay.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	t.Cleanup(func() { _ = assoc.Close() })

	pc := assoc.PacketConn()
	require.NotNil(t, pc.LocalAddr())
	require.NoError(t, pc.SetDeadline(time.Now().Add(3*time.Second)))
	require.NoError(t, pc.SetReadDeadline(time.Now().Add(3*time.Second)))
	require.NoError(t, pc.SetWriteDeadline(time.Now().Add(3*time.Second)))

	// WriteTo via *net.UDPAddr (encapsulates into a SOCKS5 datagram).
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}
	_, err = pc.WriteTo([]byte("ping"), dst)
	require.NoError(t, err)

	buf := make([]byte, 64)
	n, from, err := pc.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, "ping", string(buf[:n]))
	require.Equal(t, "socks5+udp", from.Network())

	// WriteTo with an unsupported addr type must fail.
	_, err = pc.WriteTo([]byte("x"), &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	require.Error(t, err)

	// Closing via the PacketConn closes the association.
	require.NoError(t, pc.Close())
}

func TestUDPAssociation_WriteToAddr(t *testing.T) {
	relay := newLocalUDP(t)
	local := newLocalUDP(t)

	assoc, err := cudp.NewAssociation(local, relay.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	t.Cleanup(func() { _ = assoc.Close() })

	_, err = assoc.WriteToAddr("127.0.0.1:9999", []byte("hi"))
	require.NoError(t, err)

	buf := make([]byte, 256)
	_ = relay.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := relay.ReadFromUDP(buf)
	require.NoError(t, err)
	dg, err := protocol.ParseDatagram(buf[:n])
	require.NoError(t, err)
	require.Equal(t, []byte("hi"), dg.Data)

	_, err = assoc.WriteToAddr("bad address", []byte("hi"))
	require.Error(t, err)
}

func TestUDPAssociation_ConfigureKeepAlive(t *testing.T) {
	relay := newLocalUDP(t)
	local := newLocalUDP(t)

	assoc, err := cudp.NewAssociation(local, relay.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	t.Cleanup(func() { _ = assoc.Close() })

	// Enable keep-alive after construction.
	assoc.ConfigureKeepAlive(20*time.Millisecond, []byte{0xAA})

	buf := make([]byte, 8)
	_ = relay.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := relay.ReadFromUDP(buf)
	require.NoError(t, err)
	require.Equal(t, []byte{0xAA}, buf[:n])

	// Reconfigure with empty payload (defaults to single zero byte).
	assoc.ConfigureKeepAlive(20*time.Millisecond, nil)
	_ = relay.SetReadDeadline(time.Now().Add(2 * time.Second))
	deadline := time.Now().Add(2 * time.Second)
	for {
		n, _, err = relay.ReadFromUDP(buf)
		require.NoError(t, err)
		if n == 1 && buf[0] == 0x00 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("did not observe zero-byte keep-alive after reconfigure")
		}
	}

	// Disable keep-alive: no more packets after the in-flight ones drain.
	assoc.ConfigureKeepAlive(0, nil)
	drainUntil := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(drainUntil) {
		_ = relay.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		_, _, _ = relay.ReadFromUDP(buf)
	}
	_ = relay.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	_, _, err = relay.ReadFromUDP(buf)
	require.Error(t, err)
	ne, ok := err.(net.Error)
	require.True(t, ok)
	require.True(t, ne.Timeout())
}
