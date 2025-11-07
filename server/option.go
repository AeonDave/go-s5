package server

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/AeonDave/go-s5/auth"
	"github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/internal/buffer"
	"github.com/AeonDave/go-s5/resolver"
	"github.com/AeonDave/go-s5/rules"
)

type Option func(s *Server)

// WithBufferPool sets the buffer pool used by the proxy I/O fast-paths.
func WithBufferPool(pool buffer.BufPool) Option {
	return func(s *Server) { s.bufferPool = pool }
}

// WithAuthMethods appends custom authenticators to the method negotiation list.
func WithAuthMethods(authMethods []auth.Authenticator) Option {
	return func(s *Server) { s.authMethods = append(s.authMethods, authMethods...) }
}

// WithCredential provides a credential store used by the default user/pass authenticator.
func WithCredential(cs auth.CredentialStore) Option {
	return func(s *Server) { s.credentials = cs }
}

// WithResolver overrides the DNS resolver used for FQDN targets.
func WithResolver(res resolver.NameResolver) Option {
	return func(s *Server) { s.resolver = res }
}

// WithRule sets the ACL evaluated before dialing the upstream target.
func WithRule(rule rules.RuleSet) Option {
	return func(s *Server) { s.rules = rule }
}

// WithRewriter installs an address rewriter that can mutate the destination before dialing.
func WithRewriter(rew handler.AddressRewriter) Option {
	return func(s *Server) { s.rewriter = rew }
}

// WithBindIP sets the bind address used for BIND/UDP sockets.
func WithBindIP(ip net.IP) Option {
	return func(s *Server) {
		if len(ip) > 0 {
			s.bindIP = append(make(net.IP, 0, len(ip)), ip...)
		}
	}
}

// WithLogger replaces the server logger implementation.
func WithLogger(l Logger) Option {
	return func(s *Server) { s.logger = l }
}

// WithDial provides a custom dial function invoked for CONNECT/BIND/ASSOCIATE.
func WithDial(dial func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(s *Server) { s.dial = dial }
}

// WithDialAndRequest is like WithDial but also exposes the parsed request.
func WithDialAndRequest(dial func(ctx context.Context, network, addr string, req *handler.Request) (net.Conn, error)) Option {
	return func(s *Server) { s.dialWithRequest = dial }
}

// WithGPool registers a goroutine pool for request handling.
func WithGPool(pool GPool) Option {
	return func(s *Server) { s.gPool = pool }
}

// WithConnectHandle replaces the default CONNECT handler.
func WithConnectHandle(h func(ctx context.Context, writer io.Writer, req *handler.Request) error) Option {
	return func(s *Server) { s.userConnectHandle = h }
}

// WithBindHandle replaces the default BIND handler.
func WithBindHandle(h func(ctx context.Context, writer io.Writer, req *handler.Request) error) Option {
	return func(s *Server) { s.userBindHandle = h }
}

// WithAssociateHandle replaces the default UDP ASSOCIATE handler.
func WithAssociateHandle(h func(ctx context.Context, writer io.Writer, req *handler.Request) error) Option {
	return func(s *Server) { s.userAssociateHandle = h }
}

// WithConnectMiddleware appends middleware executed before the CONNECT handler.
func WithConnectMiddleware(m handler.Middleware) Option {
	return func(s *Server) { s.userConnectMiddlewares = append(s.userConnectMiddlewares, m) }
}

// WithBindMiddleware appends middleware executed before the BIND handler.
func WithBindMiddleware(m handler.Middleware) Option {
	return func(s *Server) { s.userBindMiddlewares = append(s.userBindMiddlewares, m) }
}

// WithAssociateMiddleware appends middleware executed before the UDP ASSOCIATE handler.
func WithAssociateMiddleware(m handler.Middleware) Option {
	return func(s *Server) { s.userAssociateMiddlewares = append(s.userAssociateMiddlewares, m) }
}

// WithUseBindIpBaseResolveAsUdpAddr forces UDP ASSOCIATE replies to advertise the bind IP.
func WithUseBindIpBaseResolveAsUdpAddr(b bool) Option {
	return func(s *Server) { s.useBindIpBaseResolveAsUdpAddr = b }
}

// WithBindAcceptTimeout sets how long the server waits for the peer during BIND.
func WithBindAcceptTimeout(d time.Duration) Option {
	return func(s *Server) { s.bindAcceptTimeout = d }
}

// WithBindPeerCheckIPOnly switches peer validation to IP-only (ignoring port).
func WithBindPeerCheckIPOnly(b bool) Option {
	return func(s *Server) { s.bindPeerCheckIPOnly = b }
}

// WithHandshakeTimeout sets a deadline for initial negotiation and request parsing.
// Zero disables the handshake deadline.
func WithHandshakeTimeout(d time.Duration) Option {
	return func(s *Server) { s.handshakeTimeout = d }
}

// WithTCPKeepAlive enables TCP keepalives on accepted connections with the given period.
// Zero disables keepalives.
func WithTCPKeepAlive(period time.Duration) Option {
	return func(s *Server) { s.tcpKeepAlivePeriod = period }
}

// WithDialer sets a custom net.Dialer for outbound connections when a custom dial is not provided.
func WithDialer(d net.Dialer) Option {
	return func(s *Server) { s.dialer = &d }
}

// WithUDPAssociateLimits configures UDP ASSOCIATE peer limits and idle cleanup.
// If maxPeers <= 0, unlimited peers are allowed. If idleTimeout <= 0, peers are not GC'd by idle.
func WithUDPAssociateLimits(maxPeers int, idleTimeout time.Duration) Option {
	return func(s *Server) {
		s.udpMaxPeers = maxPeers
		s.udpIdleTimeout = idleTimeout
	}
}

// WithBaseContext installs a base context factory that is invoked once per listener.
// ServeContext derives each connection context from the returned value.
func WithBaseContext(fn func(net.Listener) context.Context) Option {
	return func(s *Server) { s.baseContext = fn }
}

// WithConnContext decorates the per-connection context before handlers and dialers run.
// The provided ctx is derived from ServeContext; return nil to keep the original value.
func WithConnContext(fn func(ctx context.Context, conn net.Conn) context.Context) Option {
	return func(s *Server) { s.connContext = fn }
}

// WithConnState registers a hook that receives connection lifecycle transitions (StateNew, StateActive, StateClosed).
func WithConnState(fn func(net.Conn, ConnState)) Option {
	return func(s *Server) { s.connStateHook = fn }
}

// WithConnMetadata installs a callback used to attach static metadata to handler.Request.Metadata.
// The returned map is shallow-copied per connection.
func WithConnMetadata(fn func(net.Conn) map[string]string) Option {
	return func(s *Server) { s.connMetadata = fn }
}
