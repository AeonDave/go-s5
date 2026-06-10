// Package rules provides the access-control hook evaluated by the SOCKS5
// server after authentication and address resolution, before dialing.
package rules

import (
	"context"

	"github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/internal/protocol"
)

// RuleSet decides whether a request may proceed. The returned context
// replaces the request context when non-nil; returning false rejects the
// request with a "connection not allowed by ruleset" reply.
type RuleSet interface {
	Allow(ctx context.Context, req *handler.Request) (context.Context, bool)
}

// PermitCommand is a RuleSet that allows or denies requests purely by SOCKS5
// command type.
type PermitCommand struct {
	EnableConnect, EnableBind, EnableAssociate bool
}

// NewPermitNone returns a RuleSet that rejects every request.
func NewPermitNone() RuleSet {
	return &PermitCommand{}
}

// NewPermitAll returns a RuleSet that allows CONNECT, BIND and UDP ASSOCIATE.
func NewPermitAll() RuleSet {
	return &PermitCommand{true, true, true}
}

// NewPermitConnAndAss returns a RuleSet that allows CONNECT and UDP
// ASSOCIATE but rejects BIND.
func NewPermitConnAndAss() RuleSet {
	return &PermitCommand{EnableConnect: true, EnableAssociate: true}
}

// Allow implements RuleSet.
func (p *PermitCommand) Allow(ctx context.Context, req *handler.Request) (context.Context, bool) {
	switch req.Command {
	case protocol.CommandConnect:
		return ctx, p.EnableConnect
	case protocol.CommandBind:
		return ctx, p.EnableBind
	case protocol.CommandAssociate:
		return ctx, p.EnableAssociate
	default:
		return ctx, false
	}
}
