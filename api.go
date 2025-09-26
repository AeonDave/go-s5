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
	"github.com/AeonDave/go-s5/client"
)

// Re-export types and constructors from the client package.
type (
	Client       = client.Client
	Credentials  = client.Credentials
	ClientOption = client.Option
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
)
