package handler

import (
	"context"
	"io"
	"net"

	"github.com/AeonDave/go-s5/auth"
	"github.com/AeonDave/go-s5/internal/protocol"
)

type AddressRewriter interface {
	Rewrite(ctx context.Context, request *Request) (context.Context, *protocol.AddrSpec)
}

type Request struct {
	protocol.Request
	Context     context.Context
	Metadata    map[string]string
	AuthContext *auth.AContext
	LocalAddr   net.Addr
	RemoteAddr  net.Addr
	DestAddr    *protocol.AddrSpec
	Reader      io.Reader
	RawDestAddr *protocol.AddrSpec
}

func ParseRequest(bufConn io.Reader) (*Request, error) {
	hd, err := protocol.ParseRequest(bufConn)
	if err != nil {
		return nil, err
	}
	return &Request{Request: hd, RawDestAddr: &hd.DstAddr, Reader: bufConn}, nil
}
