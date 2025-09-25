package rules

import (
	"context"

	"github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/internal/protocol"
)

type RuleSet interface {
	Allow(ctx context.Context, req *handler.Request) (context.Context, bool)
}

type PermitCommand struct {
	EnableConnect, EnableBind, EnableAssociate bool
}

func NewPermitNone() RuleSet {
	return &PermitCommand{}
}

func NewPermitAll() RuleSet {
	return &PermitCommand{true, true, true}
}

func NewPermitConnAndAss() RuleSet {
	return &PermitCommand{EnableConnect: true, EnableAssociate: true}
}

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
