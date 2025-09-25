package socks5

import (
	"context"
	"go-s5/rules"
	"testing"

	"go-s5/handler"
	"go-s5/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestPermitCommand(t *testing.T) {
	var r rules.RuleSet
	var ok bool
	ctx := context.Background()

	r = rules.NewPermitAll()
	_, ok = r.Allow(ctx, &handler.Request{Request: protocol.Request{Command: protocol.CommandConnect}})
	require.True(t, ok)
	_, ok = r.Allow(ctx, &handler.Request{Request: protocol.Request{Command: protocol.CommandBind}})
	require.True(t, ok)
	_, ok = r.Allow(ctx, &handler.Request{Request: protocol.Request{Command: protocol.CommandAssociate}})
	require.True(t, ok)
	_, ok = r.Allow(ctx, &handler.Request{Request: protocol.Request{Command: 0x00}})
	require.False(t, ok)

	r = rules.NewPermitConnAndAss()
	_, ok = r.Allow(ctx, &handler.Request{Request: protocol.Request{Command: protocol.CommandConnect}})
	require.True(t, ok)
	_, ok = r.Allow(ctx, &handler.Request{Request: protocol.Request{Command: protocol.CommandBind}})
	require.False(t, ok)
	_, ok = r.Allow(ctx, &handler.Request{Request: protocol.Request{Command: protocol.CommandAssociate}})
	require.True(t, ok)
	_, ok = r.Allow(ctx, &handler.Request{Request: protocol.Request{Command: 0x00}})
	require.False(t, ok)

	r = rules.NewPermitNone()
	_, ok = r.Allow(ctx, &handler.Request{Request: protocol.Request{Command: protocol.CommandConnect}})
	require.False(t, ok)
	_, ok = r.Allow(ctx, &handler.Request{Request: protocol.Request{Command: protocol.CommandBind}})
	require.False(t, ok)
	_, ok = r.Allow(ctx, &handler.Request{Request: protocol.Request{Command: protocol.CommandAssociate}})
	require.False(t, ok)
	_, ok = r.Allow(ctx, &handler.Request{Request: protocol.Request{Command: 0x00}})
	require.False(t, ok)
}
