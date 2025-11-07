package server

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/internal/protocol"
)

func (sf *Server) handleRequest(parent context.Context, write io.Writer, req *handler.Request) error {
	var err error
	ctx := parent
	if req.Context != nil {
		ctx = req.Context
	}
	if ctx == nil {
		ctx = context.Background()
	}
	setCtx := func(next context.Context) {
		if next != nil {
			ctx = next
			req.Context = ctx
		}
	}
	req.Context = ctx

	// Work on a copy to avoid mutating RawDestAddr
	destCopy := *req.RawDestAddr
	if destCopy.FQDN != "" {
		var ip net.IP
		var resolveCtx context.Context
		resolveCtx, ip, err = sf.resolver.Resolve(ctx, destCopy.FQDN)
		setCtx(resolveCtx)
		if err != nil {
			if err := SendReply(write, protocol.RepHostUnreachable, nil); err != nil {
				return fmt.Errorf(fmtFailedSendReply, err)
			}
			return fmt.Errorf("failed to resolve destination[%v], %v", destCopy.FQDN, err)
		}
		destCopy.IP = ip
	}

	req.DestAddr = &destCopy
	if sf.rewriter != nil {
		rewriterCtx, rewritten := sf.rewriter.Rewrite(ctx, req)
		setCtx(rewriterCtx)
		if rewritten != nil {
			req.DestAddr = rewritten
		}
	}

	var allowCtx context.Context
	var ok bool
	allowCtx, ok = sf.rules.Allow(ctx, req)
	setCtx(allowCtx)
	if !ok {
		if err := SendReply(write, protocol.RepRuleFailure, nil); err != nil {
			return fmt.Errorf(fmtFailedSendReply, err)
		}
		return fmt.Errorf("bind to %v blocked by rules", req.RawDestAddr)
	}

	h, err := sf.getHandler(req.Command)
	if err != nil {
		if err := SendReply(write, protocol.RepCommandNotSupported, nil); err != nil {
			return fmt.Errorf(fmtFailedSendReply, err)
		}
		return err
	}
	return h(ctx, write, req)
}

func (sf *Server) getHandler(command uint8) (handler.Handler, error) {
	switch command {
	case protocol.CommandConnect:
		return sf.buildHandler(sf.handleConnect, sf.userConnectHandle, sf.userConnectMiddlewares), nil
	case protocol.CommandBind:
		return sf.buildHandler(sf.handleBind, sf.userBindHandle, sf.userBindMiddlewares), nil
	case protocol.CommandAssociate:
		return sf.buildHandler(sf.handleAssociate, sf.userAssociateHandle, sf.userAssociateMiddlewares), nil
	default:
		return nil, fmt.Errorf("unsupported command[%v]", command)
	}
}

func (sf *Server) buildHandler(defaultH handler.Handler, userH handler.Handler, mws handler.MiddlewareChain) handler.Handler {
	last := defaultH
	if userH != nil {
		last = userH
	}
	if len(mws) == 0 {
		return last
	}
	return func(ctx context.Context, writer io.Writer, request *handler.Request) error {
		return mws.Execute(ctx, writer, request, last)
	}
}
