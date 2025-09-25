package socks5_test

import (
	"context"
	"crypto/tls"
	"fmt"
	socks5 "go-s5"
	"go-s5/auth"
	"go-s5/handler"
	"go-s5/internal/buffer"
	"go-s5/internal/protocol"
	"go-s5/resolver"
	"go-s5/rules"
	"io"
	"net"
	"time"
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
func ExampleNewServer_basic() {
	srv := socks5.NewServer(
		socks5.WithCredential(auth.StaticCredentials{"user": "pass"}),
		socks5.WithBindIP(net.IPv4(127, 0, 0, 1)),
		socks5.WithResolver(resolver.DNSResolver{}),
		socks5.WithRule(rules.NewPermitAll()),
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
	srv := socks5.NewServer(
		socks5.WithHandshakeTimeout(2*time.Second),
		socks5.WithTCPKeepAlive(30*time.Second),
		socks5.WithDialer(d),
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		}),
		socks5.WithDialAndRequest(func(ctx context.Context, network, addr string, req *handler.Request) (net.Conn, error) {
			// could inspect req.AuthContext/req.DestAddr here
			return d.DialContext(ctx, network, addr)
		}),
	)
	fmt.Println(srv != nil)
	// Output: true
}

// Example demonstrating UDP/BIND tuning knobs.
func Example_options_udpAndBind() {
	srv := socks5.NewServer(
		socks5.WithUseBindIpBaseResolveAsUdpAddr(true),
		socks5.WithBindAcceptTimeout(500*time.Millisecond),
		socks5.WithBindPeerCheckIPOnly(true),
		socks5.WithUDPAssociateLimits(1024, 2*time.Minute),
	)
	fmt.Println(srv != nil)
	// Output: true
}

// Example showing custom buffer pool and goroutine pool.
func Example_options_bufferAndPool() {
	srv := socks5.NewServer(
		socks5.WithBufferPool(buffer.NewPool(64*1024)),
		socks5.WithGPool(gpool{}),
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
	srv := socks5.NewServer()
	// In main(): _ = srv.ListenAndServeTLS("tcp", ":1080", tlsCfg)
	fmt.Println(tlsCfg.ClientAuth == tls.RequireAndVerifyClientCert && srv != nil)
	// Output: true
}

// Example plugging in middleware and custom handlers for commands.
func Example_handlers_and_middleware() {
	srv := socks5.NewServer(
		socks5.WithConnectMiddleware(func(ctx context.Context, w io.Writer, r *handler.Request) error { return nil }),
		socks5.WithBindMiddleware(func(ctx context.Context, w io.Writer, r *handler.Request) error { return nil }),
		socks5.WithAssociateMiddleware(func(ctx context.Context, w io.Writer, r *handler.Request) error { return nil }),
		socks5.WithConnectHandle(func(ctx context.Context, w io.Writer, r *handler.Request) error { return nil }),
		socks5.WithBindHandle(func(ctx context.Context, w io.Writer, r *handler.Request) error { return nil }),
		socks5.WithAssociateHandle(func(ctx context.Context, w io.Writer, r *handler.Request) error { return nil }),
	)
	fmt.Println(srv != nil)
	// Output: true
}

// Example for a custom NameResolver.
func Example_customResolver() {
	srv := socks5.NewServer(socks5.WithResolver(exampleResolver{}))
	fmt.Println(srv != nil)
	// Output: true
}

// Example for a custom RuleSet.
func Example_customRules() {
	srv := socks5.NewServer(socks5.WithRule(onlyConnectRule{}))
	fmt.Println(srv != nil)
	// Output: true
}

// Example for an address rewriter.
func Example_customRewriter() {
	srv := socks5.NewServer(socks5.WithRewriter(rewriteAll{}))
	fmt.Println(srv != nil)
	// Output: true
}
