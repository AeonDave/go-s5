// Package resolver abstracts destination hostname resolution for the SOCKS5
// server, allowing custom DNS strategies (split-horizon, caching, DoH, ...)
// via the NameResolver interface.
package resolver

import (
	"context"
	"net"
)

// NameResolver resolves a destination hostname to an IP address. The
// returned context replaces the request context when non-nil, letting
// resolvers attach values for downstream rules and handlers.
type NameResolver interface {
	Resolve(ctx context.Context, name string) (context.Context, net.IP, error)
}

// DNSResolver is the default NameResolver backed by net.DefaultResolver.
type DNSResolver struct{}

// Resolve implements NameResolver. It prefers IPv4 results to match typical
// SOCKS UDP expectations when the client is IPv4, falling back to the first
// returned address.
func (DNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addr, err := net.DefaultResolver.LookupIPAddr(ctx, name)
	if err != nil || len(addr) == 0 {
		return ctx, nil, err
	}

	for _, a := range addr {
		if ip4 := a.IP.To4(); ip4 != nil {
			return ctx, ip4, nil
		}
	}
	return ctx, addr[0].IP, nil
}
