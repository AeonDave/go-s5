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
	"net"
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

type GPool interface {
	Submit(f func()) error
}

type ConnState int

const (
	StateNew ConnState = iota
	StateActive
	StateClosed
)

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

	linkTracker *linkquality.Tracker
	activeConns int64
}

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

	return srv
}

func (sf *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return sf.ServeContext(context.Background(), l)
}

func (sf *Server) ListenAndServeTLS(network, addr string, c *tls.Config) error {
	l, err := tls.Listen(network, addr, c)
	if err != nil {
		return err
	}
	return sf.ServeContext(context.Background(), l)
}

func (sf *Server) Serve(l net.Listener) error {
	return sf.ServeContext(context.Background(), l)
}

// ServeContext serves SOCKS5 on l until ctx is done or an unrecoverable error occurs.
func (sf *Server) ServeContext(ctx context.Context, l net.Listener) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if sf.baseContext != nil {
		if base := sf.baseContext(l); base != nil {
			ctx = base
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var closeOnce sync.Once
	closeListener := func() { closeOnce.Do(func() { _ = l.Close() }) }
	defer closeListener()
	go func() {
		<-ctx.Done()
		closeListener()
	}()
	var tempDelay time.Duration
	for {
		conn, err := sf.acceptWithBackoff(l, &tempDelay)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if conn == nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		tempDelay = 0
		sf.onAcceptedConn(ctx, conn)
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
	active := atomic.AddInt64(&sf.activeConns, 1)
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
		active := atomic.AddInt64(&sf.activeConns, -1)
		if sf.logConnections && sf.logger != nil {
			sf.logger.Infof("closed %s -> %s (active=%d)", conn.RemoteAddr(), conn.LocalAddr(), active)
		}
	})
}

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

	bufConn := bufio.NewReader(conn)
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
	if !sf.isCommandSupported(request.Request.Command) {
		_ = SendReply(conn, protocol.RepCommandNotSupported, nil)
		return fmt.Errorf("unrecognized command[%d]", request.Request.Command)
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
		for _, method := range methods {
			if authMethod.GetCode() == method {
				return authMethod.Authenticate(bufConn, conn, userAddr)
			}
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
	clone := make(map[string]string, len(raw))
	for k, v := range raw {
		clone[k] = v
	}
	return clone
}

// LinkQualityTracker returns the tracker used for outbound hops, if enabled.
func (sf *Server) LinkQualityTracker() *linkquality.Tracker {
	return sf.linkTracker
}
