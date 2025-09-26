package server

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/internal/protocol"
)

func (sf *Server) handleRequest(write io.Writer, req *handler.Request) error {
	var err error

	ctx := context.Background()

	// Work on a copy to avoid mutating RawDestAddr
	destCopy := *req.RawDestAddr
	if destCopy.FQDN != "" {
		var ip net.IP
		ctx, ip, err = sf.resolver.Resolve(ctx, destCopy.FQDN)
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
		ctx, req.DestAddr = sf.rewriter.Rewrite(ctx, req)
	}

	var ok bool
	ctx, ok = sf.rules.Allow(ctx, req)
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
