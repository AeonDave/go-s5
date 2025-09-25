package handler

import (
	"context"
	"go-s5/auth"
	"go-s5/internal/protocol"
	"io"
	"net"
)

type AddressRewriter interface {
	Rewrite(ctx context.Context, request *Request) (context.Context, *protocol.AddrSpec)
}

type Request struct {
	protocol.Request
	AuthContext *auth.AuthContext
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
