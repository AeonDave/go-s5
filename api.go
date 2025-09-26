package s5

// Public client API re-exports for convenience.
//
// Example usage:
//   conn, _ := net.Dial("tcp", "127.0.0.1:1080")
//   cli := NewClient()
//   _, _ = cli.Handshake(ctx, conn, nil)
//   dst, _ := protocol.ParseAddrSpec("example.com:80")
//   _, _ = cli.Connect(ctx, conn, dst)

import (
	"context"
	"github.com/AeonDave/go-s5/client"
	"net"
	"time"
)

// Re-export types and constructors from the client package.
type (
	Client       = client.Client
	Credentials  = client.Credentials
	ClientOption = client.Option
	Hop          = client.Hop
)

// Client options
//
//goland:noinspection GoUnusedGlobalVariable
var (
	NewClient                  = client.New
	ClientWithHandshakeTimeout = client.WithHandshakeTimeout
	ClientWithIOTimeout        = client.WithIOTimeout
	ClientWithMethods          = client.WithMethods
	ClientWithUDPLocalAddr     = client.WithUDPLocalAddr
	ClientWithDialer           = client.WithDialer
)

// DialChain returns a ready net.Conn after chaining through the provided hops
// and CONNECTing to the final target. It creates a temporary Client with the given options.
func DialChain(ctx context.Context, chain []Hop, finalTarget string, dialTimeout time.Duration, opts ...ClientOption) (net.Conn, error) {
	c := client.New(opts...)
	return c.DialChain(ctx, chain, finalTarget, dialTimeout)
}
