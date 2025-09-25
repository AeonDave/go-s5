package s5

import (
	"context"
	"go-s5/auth"
	"go-s5/handler"
	"go-s5/internal/buffer"
	"go-s5/resolver"
	"go-s5/rules"
	"io"
	"net"
	"time"
)

type Option func(s *Server)

func WithBufferPool(pool buffer.BufPool) Option {
	return func(s *Server) { s.bufferPool = pool }
}

func WithAuthMethods(authMethods []auth.Authenticator) Option {
	return func(s *Server) { s.authMethods = append(s.authMethods, authMethods...) }
}

func WithCredential(cs auth.CredentialStore) Option {
	return func(s *Server) { s.credentials = cs }
}

func WithResolver(res resolver.NameResolver) Option {
	return func(s *Server) { s.resolver = res }
}

func WithRule(rule rules.RuleSet) Option {
	return func(s *Server) { s.rules = rule }
}

func WithRewriter(rew handler.AddressRewriter) Option {
	return func(s *Server) { s.rewriter = rew }
}

func WithBindIP(ip net.IP) Option {
	return func(s *Server) {
		if len(ip) > 0 {
			s.bindIP = append(make(net.IP, 0, len(ip)), ip...)
		}
	}
}

func WithLogger(l Logger) Option {
	return func(s *Server) { s.logger = l }
}

func WithDial(dial func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(s *Server) { s.dial = dial }
}

func WithDialAndRequest(dial func(ctx context.Context, network, addr string, req *handler.Request) (net.Conn, error)) Option {
	return func(s *Server) { s.dialWithRequest = dial }
}

func WithGPool(pool GPool) Option {
	return func(s *Server) { s.gPool = pool }
}

func WithConnectHandle(h func(ctx context.Context, writer io.Writer, req *handler.Request) error) Option {
	return func(s *Server) { s.userConnectHandle = h }
}

func WithBindHandle(h func(ctx context.Context, writer io.Writer, req *handler.Request) error) Option {
	return func(s *Server) { s.userBindHandle = h }
}

func WithAssociateHandle(h func(ctx context.Context, writer io.Writer, req *handler.Request) error) Option {
	return func(s *Server) { s.userAssociateHandle = h }
}

func WithConnectMiddleware(m handler.Middleware) Option {
	return func(s *Server) { s.userConnectMiddlewares = append(s.userConnectMiddlewares, m) }
}

func WithBindMiddleware(m handler.Middleware) Option {
	return func(s *Server) { s.userBindMiddlewares = append(s.userBindMiddlewares, m) }
}

func WithAssociateMiddleware(m handler.Middleware) Option {
	return func(s *Server) { s.userAssociateMiddlewares = append(s.userAssociateMiddlewares, m) }
}

func WithUseBindIpBaseResolveAsUdpAddr(b bool) Option {
	return func(s *Server) { s.useBindIpBaseResolveAsUdpAddr = b }
}

func WithBindAcceptTimeout(d time.Duration) Option {
	return func(s *Server) { s.bindAcceptTimeout = d }
}

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
