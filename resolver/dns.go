package resolver

import (
	"context"
	"net"
)

type NameResolver interface {
	Resolve(ctx context.Context, name string) (context.Context, net.IP, error)
}

type DNSResolver struct{}

func (DNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addr, err := net.DefaultResolver.LookupIPAddr(ctx, name)
	if err != nil || len(addr) == 0 {
		return ctx, nil, err
	}

	// Prefer IPv4 if present to match typical SOCKS UDP expectations when the client is IPv4.
	for _, a := range addr {
		if ip4 := a.IP.To4(); ip4 != nil {
			return ctx, ip4, nil
		}
	}
	// Fallback to the first address.
	return ctx, addr[0].IP, nil
}
