package server

import (
	"context"
	"fmt"
	"io"

	"github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/internal/protocol"
)

func (sf *Server) handleConnect(ctx context.Context, writer io.Writer, request *handler.Request) error {
	target, err := sf.dialOut(ctx, "tcp", request.DestAddr.String(), request)
	if err != nil {
		resp := mapConnectDialError(err)
		if err := SendReply(writer, resp, nil); err != nil {
			return fmt.Errorf(fmtFailedSendReply, err)
		}
		return fmt.Errorf("connect to %v failed, %v", request.RawDestAddr, err)
	}
	defer sf.closeIgnoreErr("target", target)

	if err := SendReply(writer, protocol.RepSuccess, target.LocalAddr()); err != nil {
		return fmt.Errorf(fmtFailedSendReply, err)
	}

	return sf.proxyDuplex(target, request.Reader, writer, target)
}
