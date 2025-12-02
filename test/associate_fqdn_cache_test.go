package socks5_test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/AeonDave/go-s5/internal/protocol"
	"github.com/AeonDave/go-s5/server"
	"github.com/stretchr/testify/require"
)

type mockResolverWithDelay struct {
	mu      sync.Mutex
	records map[string]net.IP
	delay   time.Duration
}

func (m *mockResolverWithDelay) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	time.Sleep(m.delay)
	if ip, ok := m.records[name]; ok {
		return ctx, ip, nil
	}
	return ctx, nil, fmt.Errorf("not found")
}

func (m *mockResolverWithDelay) Update(name string, ip net.IP) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[name] = ip
}

func startUDPBackend(t *testing.T, network, addr string, response []byte) (*net.UDPAddr, func()) {
	t.Helper()

	conn, err := net.ListenPacket(network, addr)
	if err != nil && network == "udp6" {
		t.Skipf("IPv6 UDP not available: %v", err)
	}
	require.NoError(t, err)

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		buf := make([]byte, 2048)
		for {
			n, r, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n > 0 {
				_, _ = conn.WriteTo(response, r)
			}
		}
	}()

	stop := func() {
		_ = conn.Close()
		<-stopped
	}

	return conn.LocalAddr().(*net.UDPAddr), stop
}

func TestSOCKS5_Associate_FQDN_Cache(t *testing.T) {
	// Mock DNS resolver
	mockDNS := &mockResolverWithDelay{
		records: make(map[string]net.IP),
		delay:   100 * time.Millisecond,
	}
	fqdn := "cache.test.com"
	mockDNS.Update(fqdn, net.ParseIP("127.0.0.1"))

	// SOCKS5 server
	listen, stop := startSocks5(t,
		server.WithResolver(mockDNS),
	)
	defer stop()

	// SOCKS5 client
	conn, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer conn.Close()

	// Handshake
	_, err = conn.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	require.NoError(t, err)
	out := make([]byte, 2)
	_, err = conn.Read(out)
	require.NoError(t, err)

	// First Associate request
	req := protocol.Request{
		Version: protocol.VersionSocks5,
		Command: protocol.CommandAssociate,
		DstAddr: protocol.AddrSpec{FQDN: fqdn, Port: 1234, AddrType: protocol.ATYPDomain},
	}
	_, err = conn.Write(req.Bytes())
	require.NoError(t, err)
	_, err = protocol.ParseReply(conn)
	require.NoError(t, err)

	// Second Associate request
	start := time.Now()
	_, err = conn.Write(req.Bytes())
	require.NoError(t, err)
	_, err = protocol.ParseReply(conn)
	require.NoError(t, err)
	duration := time.Since(start)

	require.Less(t, duration, mockDNS.delay, "The second request should be faster due to caching")
}

func TestSOCKS5_Associate_FQDN_UsesResolvedIPForCacheKey(t *testing.T) {
	mockDNS := &mockResolverWithDelay{records: make(map[string]net.IP)}
	fqdn := "cache-key.test"

	// Backends on the same port but different IP families.
	v4Addr, stopV4 := startUDPBackend(t, "udp4", "127.0.0.1:0", []byte("v4"))
	defer stopV4()

	v6Addr, stopV6 := startUDPBackend(t, "udp6", "[::1]:0", []byte("v6"))
	defer stopV6()

	mockDNS.Update(fqdn, v4Addr.IP)

	listen, stop := startSocks5(t,
		server.WithResolver(mockDNS),
	)
	defer stop()

	ctrl, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer ctrl.Close()

	// SOCKS5 handshake + ASSOCIATE request
	_, err = ctrl.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	require.NoError(t, err)
	methodReply := make([]byte, 2)
	_, err = ctrl.Read(methodReply)
	require.NoError(t, err)

	req := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandAssociate,
		DstAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 0, AddrType: protocol.ATYPIPv4}}
	_, err = ctrl.Write(req.Bytes())
	require.NoError(t, err)
	rep, err := protocol.ParseReply(ctrl)
	require.NoError(t, err)

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer client.Close()

	sendDatagram := func(port int, payload []byte) []byte {
		dg := protocol.Datagram{DstAddr: protocol.AddrSpec{FQDN: fqdn, Port: port, AddrType: protocol.ATYPDomain}, Data: payload}
		_, err := client.WriteTo(dg.Bytes(), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: rep.BndAddr.Port})
		require.NoError(t, err)

		buf := make([]byte, 2048)
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := client.ReadFrom(buf)
		require.NoError(t, err)
		_ = client.SetReadDeadline(time.Time{})
		parsed, err := protocol.ParseDatagram(buf[:n])
		require.NoError(t, err)
		return parsed.Data
	}

	// First datagram resolves to IPv4 backend.
	require.Equal(t, []byte("v4"), sendDatagram(v4Addr.Port, []byte("ping4")))

	// Update DNS to IPv6 and ensure the cache key changes so a new upstream connection is created.
	mockDNS.Update(fqdn, v6Addr.IP)
	require.Equal(t, []byte("v6"), sendDatagram(v6Addr.Port, []byte("ping6")))
}
