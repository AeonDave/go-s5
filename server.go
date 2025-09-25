package s5

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"go-s5/auth"
	"go-s5/handler"
	"go-s5/internal/buffer"
	"go-s5/internal/protocol"
	"go-s5/resolver"
	"go-s5/rules"
	"io"
	"log"
	"net"
	"time"
)

type GPool interface {
	Submit(f func()) error
}

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
}

func NewServer(opts ...Option) *Server {
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
	return sf.Serve(l)
}

func (sf *Server) ListenAndServeTLS(network, addr string, c *tls.Config) error {
	l, err := tls.Listen(network, addr, c)
	if err != nil {
		return err
	}
	return sf.Serve(l)
}

func (sf *Server) Serve(l net.Listener) error {
	defer func(l net.Listener) { _ = l.Close() }(l)
	var tempDelay time.Duration
	for {
		conn, err := sf.acceptWithBackoff(l, &tempDelay)
		if err != nil {
			return err
		}
		if conn == nil {
			continue
		}
		tempDelay = 0
		sf.onAcceptedConn(conn)
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

func (sf *Server) onAcceptedConn(conn net.Conn) {
	if sf.tcpKeepAlivePeriod > 0 {
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetKeepAlive(true)
			_ = tcp.SetKeepAlivePeriod(sf.tcpKeepAlivePeriod)
		}
	}
	sf.goFunc(func() {
		if err := sf.ServeConn(conn); err != nil {
			sf.logger.Errorf("server: %v", err)
		}
	})
}

func (sf *Server) ServeConn(conn net.Conn) error {
	defer func(conn net.Conn) { _ = conn.Close() }(conn)
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
	return sf.handleRequest(conn, request)
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

func (sf *Server) enrichAuthFromTLS(conn net.Conn, authContext *auth.AuthContext) {
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
	if ip := firstIPFromCert(leaf); ip != "" {
		authContext.Payload["tls.san.ip"] = ip
	}
	sum := sha256.Sum256(leaf.Raw)
	authContext.Payload["tls.fingerprint.sha256"] = hex.EncodeToString(sum[:])
}

func firstIPFromCert(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if len(cert.IPAddresses) > 0 {
		return cert.IPAddresses[0].String()
	}
	return ""
}

func (sf *Server) authenticate(conn io.Writer, bufConn io.Reader, userAddr string, methods []byte) (*auth.AuthContext, error) {
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
