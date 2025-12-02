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
