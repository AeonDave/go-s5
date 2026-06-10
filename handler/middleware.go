// Package handler defines the request type flowing through the SOCKS5
// server, the per-command Handler/Middleware extension points, and the
// AddressRewriter hook for mutating destinations before dialing.
package handler

import (
	"context"
	"io"
)

// Handler processes one SOCKS5 command (CONNECT, BIND or UDP ASSOCIATE).
// writer is the client control connection; the handler is responsible for
// sending the SOCKS reply and relaying traffic.
type Handler func(ctx context.Context, writer io.Writer, req *Request) error

// Middleware runs before the command handler. Returning a non-nil error
// aborts the request without invoking the handler.
type Middleware func(ctx context.Context, writer io.Writer, req *Request) error

// MiddlewareChain is an ordered list of Middleware executed front to back.
type MiddlewareChain []Middleware

// Execute runs every middleware in order and, if none failed, the final
// handler.
func (m MiddlewareChain) Execute(ctx context.Context, writer io.Writer, req *Request, last Handler) error {
	for _, mw := range m {
		if err := mw(ctx, writer, req); err != nil {
			return err
		}
	}
	return last(ctx, writer, req)
}
