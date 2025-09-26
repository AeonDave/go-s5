package socks5_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/AeonDave/go-s5/auth"
	"github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/internal/buffer"
	"github.com/AeonDave/go-s5/internal/protocol"
	"github.com/AeonDave/go-s5/resolver"
	"github.com/AeonDave/go-s5/rules"
	server "github.com/AeonDave/go-s5/server"
)

// simple goroutine pool for examples
type gpool struct{}

func (gpool) Submit(f func()) error { go f(); return nil }

// custom example resolver
type exampleResolver struct{}

func (exampleResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, net.ParseIP("127.0.0.1"), nil
}

// custom ruleset that only allows CONNECT
type onlyConnectRule struct{}

func (onlyConnectRule) Allow(ctx context.Context, req *handler.Request) (context.Context, bool) {
	return ctx, req.Command == protocol.CommandConnect
}

// custom rewriter forcing all traffic to 1.2.3.4:80
type rewriteAll struct{}

func (rewriteAll) Rewrite(ctx context.Context, _ *handler.Request) (context.Context, *protocol.AddrSpec) {
	return ctx, &protocol.AddrSpec{IP: net.ParseIP("1.2.3.4"), Port: 80, AddrType: protocol.ATYPIPv4}
}

// Example demonstrating basic server construction with options.
func ExampleNew_basic() {
	srv := server.New(
		server.WithCredential(auth.StaticCredentials{"user": "pass"}),
		server.WithBindIP(net.IPv4(127, 0, 0, 1)),
		server.WithResolver(resolver.DNSResolver{}),
		server.WithRule(rules.NewPermitAll()),
	)
	// Use srv.ListenAndServe("tcp", ":1080") in your main.
	fmt.Println(srv != nil)
	// Output: true
}

// Simple check that default resolver can handle an IP literal without error.
func ExampleDefaultResolver() {
	res := resolver.DNSResolver{}
	_, ip, err := res.Resolve(context.Background(), "127.0.0.1")
	fmt.Println(err == nil && ip != nil)
	// Output: true
}

// Sanity check for rules factory with a fabricated request.
func ExampleNewPermitAll() {
	rs := rules.NewPermitAll()
	// Minimal request with CONNECT command
	req := &handler.Request{Request: protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandConnect}}
	_, ok := rs.Allow(context.Background(), req)
	fmt.Println(ok)
	// Output: true
}

// Example configuring timeouts, keepalive, and custom dialers.
func Example_options_dialsAndTimeouts() {
	d := net.Dialer{Timeout: 5 * time.Second}
	srv := server.New(
		server.WithHandshakeTimeout(2*time.Second),
		server.WithTCPKeepAlive(30*time.Second),
		server.WithDialer(d),
		server.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		}),
		server.WithDialAndRequest(func(ctx context.Context, network, addr string, req *handler.Request) (net.Conn, error) {
			// could inspect req.AuthContext/req.DestAddr here
			return d.DialContext(ctx, network, addr)
		}),
	)
	fmt.Println(srv != nil)
	// Output: true
}

// Example demonstrating UDP/BIND tuning knobs.
func Example_options_udpAndBind() {
	srv := server.New(
		server.WithUseBindIpBaseResolveAsUdpAddr(true),
		server.WithBindAcceptTimeout(500*time.Millisecond),
		server.WithBindPeerCheckIPOnly(true),
		server.WithUDPAssociateLimits(1024, 2*time.Minute),
	)
	fmt.Println(srv != nil)
	// Output: true
}

// Example showing custom buffer pool and goroutine pool.
func Example_options_bufferAndPool() {
	srv := server.New(
		server.WithBufferPool(buffer.NewPool(64*1024)),
		server.WithGPool(gpool{}),
	)
	fmt.Println(srv != nil)
	// Output: true
}

// Example configuring mutual TLS (mTLS) with client certificate verification.
func Example_options_mtls() {
	// Prepare TLS config elsewhere with real certs & CA.
	tlsCfg := &tls.Config{
		// Certificates: []tls.Certificate{serverCert},
		// ClientCAs:    caPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	srv := server.New()
	// In main(): _ = srv.ListenAndServeTLS("tcp", ":1080", tlsCfg)
	fmt.Println(tlsCfg.ClientAuth == tls.RequireAndVerifyClientCert && srv != nil)
	// Output: true
}

// Example plugging in middleware and custom handlers for commands.
func Example_handlers_and_middleware() {
	srv := server.New(
		server.WithConnectMiddleware(func(ctx context.Context, w io.Writer, r *handler.Request) error { return nil }),
		server.WithBindMiddleware(func(ctx context.Context, w io.Writer, r *handler.Request) error { return nil }),
		server.WithAssociateMiddleware(func(ctx context.Context, w io.Writer, r *handler.Request) error { return nil }),
		server.WithConnectHandle(func(ctx context.Context, w io.Writer, r *handler.Request) error { return nil }),
		server.WithBindHandle(func(ctx context.Context, w io.Writer, r *handler.Request) error { return nil }),
		server.WithAssociateHandle(func(ctx context.Context, w io.Writer, r *handler.Request) error { return nil }),
	)
	fmt.Println(srv != nil)
	// Output: true
}

// Example for a custom NameResolver.
func Example_customResolver() {
	srv := server.New(server.WithResolver(exampleResolver{}))
	fmt.Println(srv != nil)
	// Output: true
}

// Example for a custom RuleSet.
func Example_customRules() {
	srv := server.New(server.WithRule(onlyConnectRule{}))
	fmt.Println(srv != nil)
	// Output: true
}

// Example for an address rewriter.
func Example_customRewriter() {
	srv := server.New(server.WithRewriter(rewriteAll{}))
	fmt.Println(srv != nil)
	// Output: true
}
