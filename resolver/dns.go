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
	return ctx, addr[0].IP, nil
}
