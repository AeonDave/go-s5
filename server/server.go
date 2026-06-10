// Package server implements a production-grade SOCKS5 server (RFC 1928) with
// CONNECT, BIND and UDP ASSOCIATE, pluggable authentication, rules,
// resolvers, middleware, metrics, admission control and graceful shutdown.
// On Linux the TCP relay uses splice(2) via io.Copy fast paths and the UDP
// relay moves batches of datagrams per syscall (recvmmsg/sendmmsg).
package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AeonDave/go-s5/auth"
	"github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/internal/buffer"
	"github.com/AeonDave/go-s5/internal/protocol"
	"github.com/AeonDave/go-s5/linkquality"
	"github.com/AeonDave/go-s5/resolver"
	"github.com/AeonDave/go-s5/rules"
)

// GPool is a goroutine pool abstraction (e.g. ants). When installed with
// WithGPool, request handling is submitted to the pool instead of spawning a
// goroutine per task; a Submit error falls back to `go`.
type GPool interface {
	Submit(f func()) error
}

// ConnState describes a connection lifecycle phase reported to the
// WithConnState hook.
type ConnState int

// Connection lifecycle states, in order of occurrence.
const (
	// StateNew is reported right after the accept loop admits a connection.
	StateNew ConnState = iota
	// StateActive is reported when the SOCKS handshake begins.
	StateActive
	// StateClosed is reported after the connection finishes.
	StateClosed
)

// Server is a SOCKS5 server (RFC 1928) supporting CONNECT, BIND and UDP
// ASSOCIATE. Construct it with New and the With* options; the zero value is
// not usable. All exported methods are safe for concurrent use.
type Server struct {
	authMethods                   []auth.Authenticator
	credentials                   auth.CredentialStore
	resolver                      resolver.NameResolver
	rules                         rules.RuleSet
	rewriter                      handler.AddressRewriter
	bindIP                        net.IP
	useBindIpBaseResolveAsUdpAddr bool
	logger                        Logger
	dial                          func(ctx context.Context, network, addr string) (net.Conn, error)
	dialWithRequest               func(ctx context.Context, network, addr string, request *handler.Request) (net.Conn, error)
	bufferPool                    buffer.BufPool
	gPool                         GPool
	userConnectHandle             func(ctx context.Context, writer io.Writer, request *handler.Request) error
	userBindHandle                func(ctx context.Context, writer io.Writer, request *handler.Request) error
	userAssociateHandle           func(ctx context.Context, writer io.Writer, request *handler.Request) error
	userConnectMiddlewares        handler.MiddlewareChain
	userBindMiddlewares           handler.MiddlewareChain
	userAssociateMiddlewares      handler.MiddlewareChain
	bindAcceptTimeout             time.Duration
	bindPeerCheckIPOnly           bool
	handshakeTimeout              time.Duration
	tcpKeepAlivePeriod            time.Duration
	dialer                        *net.Dialer
	udpMaxPeers                   int
	udpIdleTimeout                time.Duration
	logConnections                bool
	baseContext                   func(net.Listener) context.Context
	connContext                   func(ctx context.Context, conn net.Conn) context.Context
	connStateHook                 func(net.Conn, ConnState)
	connMetadata                  func(net.Conn) map[string]string

	linkTracker    *linkquality.Tracker
	activeConns    atomic.Int64
	maxConnections int
	rateLimiter    *ipRateLimiter
	metrics        Metrics
	dialFQDN       bool

	// Precomputed command handler chains (set once in New).
	connectHandler   handler.Handler
	bindHandler      handler.Handler
	associateHandler handler.Handler

	mu         sync.Mutex
	listeners  map[net.Listener]context.CancelFunc
	inShutdown atomic.Bool
}

// ErrServerClosed is returned by Serve, ServeContext, ListenAndServe and
// ListenAndServeTLS after a call to Shutdown or Close.
var ErrServerClosed = errors.New("socks5: server closed")

// bufioReaderPool recycles per-connection handshake readers. A reader is
// returned to the pool only after the whole request lifecycle ends, so
// handler.Request.Reader must not be retained past the request (same contract
// as net/http request bodies).
var bufioReaderPool sync.Pool

func newBufioReader(r io.Reader) *bufio.Reader {
	if v := bufioReaderPool.Get(); v != nil {
		br := v.(*bufio.Reader)
		br.Reset(r)
		return br
	}
	return bufio.NewReader(r)
}

func putBufioReader(br *bufio.Reader) {
	br.Reset(nil)
	bufioReaderPool.Put(br)
}

// New builds a Server with the given options. Without WithCredential or
// WithAuthMethods the server accepts unauthenticated clients (NoAuth).
func New(opts ...Option) *Server {
	srv := &Server{
		authMethods: []auth.Authenticator{},
		bufferPool:  buffer.NewPool(32 * 1024),
		resolver:    resolver.DNSResolver{},
		rules:       rules.NewPermitAll(),
		logger:      NewLogger(log.New(io.Discard, "socks5: ", log.LstdFlags)),
	}

	for _, opt := range opts {
		opt(srv)
	}

	if len(srv.authMethods) == 0 {
		if srv.credentials != nil {
			srv.authMethods = []auth.Authenticator{&auth.UserPassAuthenticator{Credentials: srv.credentials}}
		} else {
			srv.authMethods = []auth.Authenticator{&auth.NoAuthAuthenticator{}}
		}
	}

	srv.buildHandlers()

	return srv
}

// ListenAndServe listens on the network address and serves SOCKS5 until the
// server is shut down. It returns ErrServerClosed after Shutdown or Close.
func (sf *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return sf.ServeContext(context.Background(), l)
}

// ListenAndServeTLS is ListenAndServe over a TLS listener. With
// tls.RequireAndVerifyClientCert the client certificate details are exposed
// to rules and handlers via the auth context (tls.* payload keys).
func (sf *Server) ListenAndServeTLS(network, addr string, c *tls.Config) error {
	l, err := tls.Listen(network, addr, c)
	if err != nil {
		return err
	}
	return sf.ServeContext(context.Background(), l)
}

// Serve accepts and serves SOCKS5 connections on l until the server is shut
// down. It returns ErrServerClosed after Shutdown or Close.
func (sf *Server) Serve(l net.Listener) error {
	return sf.ServeContext(context.Background(), l)
}

// ServeContext serves SOCKS5 on l until ctx is done, Shutdown/Close is called,
// or an unrecoverable error occurs. Canceling ctx tears down every active
// connection; Shutdown lets in-flight connections finish.
func (sf *Server) ServeContext(ctx context.Context, l net.Listener) error {
	if sf.inShutdown.Load() {
		return ErrServerClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if sf.baseContext != nil {
		if base := sf.baseContext(l); base != nil {
			ctx = base
		}
	}
	connCtx, cancelConns := context.WithCancel(ctx)
	sf.registerListener(l, cancelConns)
	defer sf.unregisterListener(l)

	var closeOnce sync.Once
	closeListener := func() { closeOnce.Do(func() { _ = l.Close() }) }
	defer closeListener()
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-ctx.Done():
			closeListener()
		case <-watchDone:
		}
	}()

	var tempDelay time.Duration
	for {
		conn, err := sf.acceptWithBackoff(l, &tempDelay)
		if err != nil {
			if ctx.Err() != nil {
				cancelConns()
				return ctx.Err()
			}
			if sf.inShutdown.Load() {
				// Graceful shutdown: stop accepting but let active
				// connections finish; Shutdown cancels connCtx after draining.
				return ErrServerClosed
			}
			cancelConns()
			return err
		}
		if conn == nil {
			if ctx.Err() != nil {
				cancelConns()
				return ctx.Err()
			}
			continue
		}
		tempDelay = 0
		if !sf.admitConn(conn) {
			continue
		}
		sf.onAcceptedConn(connCtx, conn)
	}
}

func (sf *Server) registerListener(l net.Listener, cancelConns context.CancelFunc) {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	if sf.listeners == nil {
		sf.listeners = make(map[net.Listener]context.CancelFunc)
	}
	sf.listeners[l] = cancelConns
}

func (sf *Server) unregisterListener(l net.Listener) {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	delete(sf.listeners, l)
}

// closeListeners closes every tracked listener; when cancelConns is true the
// per-listener connection contexts are canceled too, killing active conns.
func (sf *Server) closeListeners(cancelConns bool) error {
	sf.mu.Lock()
	defer sf.mu.Unlock()
	var err error
	for l, cancel := range sf.listeners {
		if cerr := l.Close(); cerr != nil && err == nil {
			err = cerr
		}
		if cancelConns {
			cancel()
		}
	}
	return err
}

// Close immediately closes all listeners and tears down every active
// connection. For a graceful stop, use Shutdown.
func (sf *Server) Close() error {
	sf.inShutdown.Store(true)
	return sf.closeListeners(true)
}

// Shutdown gracefully stops the server: it closes all listeners so no new
// connections are accepted, then polls until active connections drain or ctx
// is done. If ctx expires first, Shutdown returns ctx.Err() with connections
// still running; call Close to force them down.
func (sf *Server) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	sf.inShutdown.Store(true)
	closeErr := sf.closeListeners(false)

	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if sf.activeConns.Load() == 0 {
			return closeErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (sf *Server) acceptWithBackoff(l net.Listener, tempDelay *time.Duration) (net.Conn, error) {
	conn, err := l.Accept()
	if err == nil {
		return conn, nil
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		if *tempDelay == 0 {
			*tempDelay = 5 * time.Millisecond
		} else {
			*tempDelay *= 2
			if m := 1 * time.Second; *tempDelay > m {
				*tempDelay = m
			}
		}
		time.Sleep(*tempDelay)
		return nil, nil
	}
	return nil, err
}

// admitConn applies pre-handshake admission control: the WithMaxConnections
// cap and the WithConnectionRateLimit per-source limiter. Both checks are
// O(1); rejected connections are closed without any SOCKS traffic. The active
// connection counter is incremented synchronously by onAcceptedConn before
// the next Accept, so the cap check is race-free.
func (sf *Server) admitConn(conn net.Conn) bool {
	if sf.maxConnections > 0 && sf.activeConns.Load() >= int64(sf.maxConnections) {
		sf.rejectConn(conn, RejectMaxConnections)
		return false
	}
	if sf.rateLimiter != nil && !sf.rateLimiter.allowConn(conn) {
		sf.rejectConn(conn, RejectRateLimited)
		return false
	}
	return true
}

func (sf *Server) rejectConn(conn net.Conn, reason RejectReason) {
	remote := conn.RemoteAddr()
	_ = conn.Close()
	if sf.metrics != nil {
		sf.metrics.ConnRejected(reason)
	}
	if sf.logConnections && sf.logger != nil {
		sf.logger.Infof("rejected %s (%s)", remote, reason)
	}
}

func (sf *Server) onAcceptedConn(ctx context.Context, conn net.Conn) {
	if sf.tcpKeepAlivePeriod > 0 {
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetKeepAlive(true)
			_ = tcp.SetKeepAlivePeriod(sf.tcpKeepAlivePeriod)
		}
	}
	connCtx := sf.decorateConnContext(ctx, conn)
	cancelableCtx, cancel := context.WithCancel(connCtx)
	sf.trackConnState(conn, StateNew)
	if sf.metrics != nil {
		sf.metrics.ConnAccepted()
	}
	active := sf.activeConns.Add(1)
	if sf.logConnections && sf.logger != nil {
		sf.logger.Infof("accepted %s -> %s (active=%d)", conn.RemoteAddr(), conn.LocalAddr(), active)
	}
	sf.goFunc(func() {
		defer cancel()
		sf.trackConnState(conn, StateActive)
		if err := sf.ServeConnContext(cancelableCtx, conn); err != nil {
			sf.logger.Errorf("server: %v", err)
		}
		sf.trackConnState(conn, StateClosed)
		if sf.metrics != nil {
			sf.metrics.ConnClosed()
		}
		active := sf.activeConns.Add(-1)
		if sf.logConnections && sf.logger != nil {
			sf.logger.Infof("closed %s -> %s (active=%d)", conn.RemoteAddr(), conn.LocalAddr(), active)
		}
	})
}

// ServeConn serves a single, already-accepted connection. Admission control
// (WithMaxConnections, WithConnectionRateLimit) is not applied: it belongs to
// the accept loop, and direct callers manage their own.
func (sf *Server) ServeConn(conn net.Conn) error {
	return sf.ServeConnContext(context.Background(), conn)
}

// ServeConnContext is like ServeConn but binds the provided context to the connection lifecycle.
func (sf *Server) ServeConnContext(ctx context.Context, conn net.Conn) error {
	if ctx == nil {
		ctx = context.Background()
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer func() {
		close(done)
		_ = conn.Close()
	}()

	sf.applyHandshakeDeadline(conn)
	if err := sf.tlsHandshakeIfAny(conn); err != nil {
		return err
	}

	bufConn := newBufioReader(conn)
	defer putBufioReader(bufConn)
	mr, err := protocol.ParseMethodRequest(bufConn)
	if err != nil || mr.Ver != protocol.VersionSocks5 {
		return protocol.ErrNotSupportVersion
	}

	userAddr := ""
	if conn.RemoteAddr() != nil {
		userAddr = conn.RemoteAddr().String()
	}
	authContext, err := sf.authenticate(conn, bufConn, userAddr, mr.Methods)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	sf.enrichAuthFromTLS(conn, authContext)

	request, err := handler.ParseRequest(bufConn)
	if err != nil {
		if errors.Is(err, protocol.ErrUnrecognizedAddrType) {
			_ = SendReply(conn, protocol.RepAddrTypeNotSupported, nil)
		}
		return fmt.Errorf("failed to read destination address: %w", err)
	}
	if !sf.isCommandSupported(request.Command) {
		_ = SendReply(conn, protocol.RepCommandNotSupported, nil)
		return fmt.Errorf("unrecognized command[%d]", request.Command)
	}

	sf.clearHandshakeDeadline(conn)
	request.AuthContext = authContext
	request.LocalAddr = conn.LocalAddr()
	request.RemoteAddr = conn.RemoteAddr()
	request.Context = ctx
	request.Metadata = sf.buildMetadata(conn)
	return sf.handleRequest(ctx, conn, request)
}

func (sf *Server) applyHandshakeDeadline(conn net.Conn) {
	if sf.handshakeTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(sf.handshakeTimeout))
	}
}

func (sf *Server) clearHandshakeDeadline(conn net.Conn) {
	if sf.handshakeTimeout > 0 {
		_ = conn.SetDeadline(time.Time{})
	}
}

func (sf *Server) tlsHandshakeIfAny(conn net.Conn) error {
	if tconn, ok := conn.(*tls.Conn); ok {
		if err := tconn.Handshake(); err != nil {
			return err
		}
	}
	return nil
}

func (sf *Server) enrichAuthFromTLS(conn net.Conn, authContext *auth.AContext) {
	tconn, ok := conn.(*tls.Conn)
	if !ok || authContext == nil {
		return
	}
	state := tconn.ConnectionState()
	if !state.HandshakeComplete || len(state.PeerCertificates) == 0 {
		return
	}
	leaf := state.PeerCertificates[0]
	if authContext.Payload == nil {
		authContext.Payload = map[string]string{}
	}
	authContext.Payload["tls.subject"] = leaf.Subject.String()
	authContext.Payload["tls.issuer"] = leaf.Issuer.String()
	if len(leaf.DNSNames) > 0 {
		authContext.Payload["tls.san.dns"] = leaf.DNSNames[0]
	}
	if ips := allIPsFromCert(leaf); len(ips) > 0 {
		authContext.Payload["tls.san.ip"] = strings.Join(ips, ",")
	}
	sum := sha256.Sum256(leaf.Raw)
	authContext.Payload["tls.fingerprint.sha256"] = hex.EncodeToString(sum[:])
}

func allIPsFromCert(cert *x509.Certificate) []string {
	if cert == nil || len(cert.IPAddresses) == 0 {
		return nil
	}
	res := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		res = append(res, ip.String())
	}
	return res
}

func (sf *Server) authenticate(conn io.Writer, bufConn io.Reader, userAddr string, methods []byte) (*auth.AContext, error) {
	for _, authMethod := range sf.authMethods {
		if slices.Contains(methods, authMethod.GetCode()) {
			return authMethod.Authenticate(bufConn, conn, userAddr)
		}
	}
	_, _ = conn.Write([]byte{protocol.VersionSocks5, protocol.MethodNoAcceptable})
	return nil, protocol.ErrNoSupportedAuth
}

func (sf *Server) isCommandSupported(cmd byte) bool {
	return cmd == protocol.CommandConnect || cmd == protocol.CommandBind || cmd == protocol.CommandAssociate
}

func (sf *Server) goFunc(f func()) {
	if sf.gPool == nil || sf.gPool.Submit(f) != nil {
		go f()
	}
}

func (sf *Server) decorateConnContext(ctx context.Context, conn net.Conn) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if sf.connContext != nil {
		if derived := sf.connContext(ctx, conn); derived != nil {
			ctx = derived
		}
	}
	return ctx
}

func (sf *Server) trackConnState(conn net.Conn, state ConnState) {
	if sf.connStateHook != nil {
		sf.connStateHook(conn, state)
	}
}

func (sf *Server) buildMetadata(conn net.Conn) map[string]string {
	if sf.connMetadata == nil {
		return nil
	}
	raw := sf.connMetadata(conn)
	if len(raw) == 0 {
		return nil
	}
	return maps.Clone(raw)
}

// LinkQualityTracker returns the tracker used for outbound hops, if enabled.
func (sf *Server) LinkQualityTracker() *linkquality.Tracker {
	return sf.linkTracker
}
