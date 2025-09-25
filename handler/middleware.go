package handler

import (
	"context"
	"io"
)

type Handler func(ctx context.Context, writer io.Writer, req *Request) error
type Middleware func(ctx context.Context, writer io.Writer, req *Request) error
type MiddlewareChain []Middleware

func (m MiddlewareChain) Execute(ctx context.Context, writer io.Writer, req *Request, last Handler) error {
	for _, mw := range m {
		if err := mw(ctx, writer, req); err != nil {
			return err
		}
	}
	return last(ctx, writer, req)
}
