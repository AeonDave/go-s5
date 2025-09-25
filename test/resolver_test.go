package socks5

import (
	"context"
	"testing"

	"github.com/AeonDave/go-s5/resolver"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDNSResolver(t *testing.T) {
	d := resolver.DNSResolver{}
	ctx := context.Background()

	_, addr, err := d.Resolve(ctx, "localhost")
	require.NoError(t, err)
	assert.True(t, addr.IsLoopback())
}
