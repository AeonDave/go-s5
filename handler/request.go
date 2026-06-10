package handler

import (
	"context"
	"io"
	"net"

	"github.com/AeonDave/go-s5/auth"
	"github.com/AeonDave/go-s5/internal/protocol"
)

// AddressRewriter mutates the destination of a request before rules run and
// the target is dialed. Returning a nil AddrSpec keeps the current
// destination; the returned context replaces the request context when
// non-nil.
type AddressRewriter interface {
	Rewrite(ctx context.Context, request *Request) (context.Context, *protocol.AddrSpec)
}

// Request is a parsed SOCKS5 command request enriched with connection state.
// RawDestAddr is the destination exactly as sent by the client; DestAddr is
// the effective destination after resolution and rewriting. Reader wraps the
// client connection and must not be retained after the request completes.
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

// ParseRequest reads a SOCKS5 command request from the client connection.
func ParseRequest(bufConn io.Reader) (*Request, error) {
	hd, err := protocol.ParseRequest(bufConn)
	if err != nil {
		return nil, err
	}
	return &Request{Request: hd, RawDestAddr: &hd.DstAddr, Reader: bufConn}, nil
}
