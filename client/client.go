package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/AeonDave/go-s5/client/internal/logging"
	ctcp "github.com/AeonDave/go-s5/client/tcp"
	cudp "github.com/AeonDave/go-s5/client/udp"
	"github.com/AeonDave/go-s5/protocol"
)

// Credentials represents username/password used during method sub-negotiation.
type Credentials struct {
	Username string
	Password string
}

// Option configures the Client.
type Option func(*Client)

// Client implements a minimal SOCKS5 client over an existing net.Conn stream.
// It supports method negotiation (NoAuth, User/Pass), CONNECT, BIND, and
// UDP ASSOCIATE. All operations work over the provided net.Conn and honor
// context deadlines combined with client timeouts.
type Client struct {
	handshakeTimeout time.Duration
	ioTimeout        time.Duration
	methods          []byte
	udpLocalAddr     *net.UDPAddr
	dialer           ContextDialer
	logger           logging.Logger
	udpKeepAliveIntv time.Duration
	udpKeepAliveData []byte
}

// New creates a new Client.
func New(opts ...Option) *Client {
	c := &Client{
		handshakeTimeout: 5 * time.Second,
		ioTimeout:        10 * time.Second,
		methods:          nil,
		udpLocalAddr:     &net.UDPAddr{IP: net.IPv4zero, Port: 0},
		logger:           logging.NewNop(),
		udpKeepAliveData: []byte{0},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// WithHandshakeTimeout sets a deadline for the initial SOCKS5 negotiation.
func WithHandshakeTimeout(d time.Duration) Option { return func(c *Client) { c.handshakeTimeout = d } }

// WithIOTimeout sets per-request read/write timeouts (CONNECT/BIND/ASSOCIATE).
func WithIOTimeout(d time.Duration) Option { return func(c *Client) { c.ioTimeout = d } }

// WithMethods overrides method preference for negotiation. If unset, the client
// prefers User/Pass when credentials are provided, otherwise NoAuth.
func WithMethods(methods []byte) Option {
	return func(c *Client) { c.methods = append([]byte(nil), methods...) }
}

// WithUDPLocalAddr binds UDP ASSOCIATE to a specific local address.
func WithUDPLocalAddr(addr *net.UDPAddr) Option { return func(c *Client) { c.udpLocalAddr = addr } }

// WithLogger installs a custom logger for helper packages. Passing nil silences
// all helper output.
func WithLogger(l Logger) Option {
	return func(c *Client) {
		if l == nil {
			c.logger = logging.NewNop()
			return
		}
		c.logger = l
	}
}

// WithUDPKeepAlive configures automatic keep-alive datagrams for UDP
// associations. When interval is non-positive the keep alive loop is disabled.
// payload may be nil, in which case a single zero byte is used.
func WithUDPKeepAlive(interval time.Duration, payload []byte) Option {
	return func(c *Client) {
		c.udpKeepAliveIntv = interval
		if len(payload) == 0 {
			c.udpKeepAliveData = []byte{0}
			return
		}
		c.udpKeepAliveData = append([]byte(nil), payload...)
	}
}

// ContextDialer is a minimal interface implemented by *net.Dialer and custom dialers.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// WithDialer sets a custom dialer used for the first TCP connection to the initial hop in DialChain.
// If not set, a net.Dialer with the provided dialTimeout will be used.
func WithDialer(d ContextDialer) Option { return func(c *Client) { c.dialer = d } }

// Handshake performs the SOCKS5 method negotiation on the given connection.
// It attempts User/Pass if creds is provided, otherwise NoAuth.
func (c *Client) Handshake(ctx context.Context, conn net.Conn, creds *Credentials) (protocol.MethodReply, error) {
	var mr protocol.MethodReply
	if conn == nil {
		return mr, errors.New("nil connection")
	}

	// Determine methods to offer
	methods := c.methods
	if len(methods) == 0 {
		if creds != nil {
			methods = []byte{protocol.MethodUserPassAuth, protocol.MethodNoAuth}
		} else {
			methods = []byte{protocol.MethodNoAuth}
		}
	}

	// Apply deadline
	cl, err := c.applyDeadline(ctx, conn, c.handshakeTimeout)
	if err != nil {
		return mr, err
	}
	if cl != nil {
		defer cl()
	}

	// Send method request
	req := protocol.NewMethodRequest(protocol.VersionSocks5, methods)
	if _, err := conn.Write(req.Bytes()); err != nil {
		return mr, fmt.Errorf("write method request: %w", err)
	}

	// Read method reply
	mr, err = protocol.ParseMethodReply(conn)
	if err != nil {
		return mr, fmt.Errorf("read method reply: %w", err)
	}

	switch mr.Method {
	case protocol.MethodNoAuth:
		return mr, nil
	case protocol.MethodUserPassAuth:
		if creds == nil {
			return mr, fmt.Errorf("server requires username/password but no credentials provided")
		}
		upr, reqErr := protocol.NewUserPassRequest(protocol.UserPassAuthVersion, []byte(creds.Username), []byte(creds.Password))
		if reqErr != nil {
			return mr, fmt.Errorf("build user/pass request: %w", reqErr)
		}
		if _, err := conn.Write(upr.Bytes()); err != nil {
			return mr, fmt.Errorf("write user/pass request: %w", err)
		}
		ur, err := protocol.ParseUserPassReply(conn)
		if err != nil {
			return mr, fmt.Errorf("read user/pass reply: %w", err)
		}
		if ur.Status != protocol.AuthSuccess {
			return mr, protocol.ErrUserAuthFailed
		}
		return mr, nil
	default:
		return mr, protocol.ErrNotSupportMethod
	}
}

// Connect sends a CONNECT request for the given destination. On success the
// caller can start piping data over conn.
func (c *Client) Connect(ctx context.Context, conn net.Conn, dst protocol.AddrSpec) (protocol.Reply, error) {
	var rep protocol.Reply
	if conn == nil {
		return rep, errors.New("nil connection")
	}

	cl, err := c.applyDeadline(ctx, conn, c.ioTimeout)
	if err != nil {
		return rep, err
	}
	if cl != nil {
		defer cl()
	}

	req := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandConnect, Reserved: 0, DstAddr: dst}
	if _, err := conn.Write(req.Bytes()); err != nil {
		return rep, fmt.Errorf("write CONNECT: %w", err)
	}
	rep, err = protocol.ParseReply(conn)
	if err != nil {
		return rep, fmt.Errorf("read CONNECT reply: %w", err)
	}
	if rep.Response != protocol.RepSuccess {
		return rep, mapRepError("CONNECT", rep.Response)
	}
	return rep, nil
}

// ConnectStream sends a CONNECT request and, on success, wraps the provided
// connection into a TCPStream helper to simplify stream operations.
func (c *Client) ConnectStream(ctx context.Context, conn net.Conn, dst protocol.AddrSpec) (*ctcp.Stream, protocol.Reply, error) {
	rep, err := c.Connect(ctx, conn, dst)
	if err != nil {
		return nil, rep, err
	}
	stream, serr := ctcp.NewStream(conn, ctcp.WithLogger(c.logger))
	if serr != nil {
		return nil, rep, serr
	}
	return stream, rep, nil
}

// BindStart sends a BIND request with the expected peer address and returns the
// first reply, which contains the bind listener address. Use BindWait to wait
// for the second reply (peer connected) before exchanging data over conn.
func (c *Client) BindStart(ctx context.Context, conn net.Conn, expect protocol.AddrSpec) (protocol.Reply, error) {
	var rep protocol.Reply
	if conn == nil {
		return rep, errors.New("nil connection")
	}

	cl, err := c.applyDeadline(ctx, conn, c.ioTimeout)
	if err != nil {
		return rep, err
	}
	if cl != nil {
		defer cl()
	}

	req := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandBind, Reserved: 0, DstAddr: expect}
	if _, err := conn.Write(req.Bytes()); err != nil {
		return rep, fmt.Errorf("write BIND: %w", err)
	}
	rep, err = protocol.ParseReply(conn)
	if err != nil {
		return rep, fmt.Errorf("read BIND first reply: %w", err)
	}
	if rep.Response != protocol.RepSuccess {
		return rep, mapRepError("BIND", rep.Response)
	}
	return rep, nil
}

// BindWait waits for the second BIND reply indicating the peer has connected.
func (c *Client) BindWait(ctx context.Context, conn net.Conn) (protocol.Reply, error) {
	var rep protocol.Reply
	if conn == nil {
		return rep, errors.New("nil connection")
	}
	cl, err := c.applyDeadline(ctx, conn, c.ioTimeout)
	if err != nil {
		return rep, err
	}
	if cl != nil {
		defer cl()
	}
	rep, err = protocol.ParseReply(conn)
	if err != nil {
		return rep, fmt.Errorf("read BIND second reply: %w", err)
	}
	if rep.Response != protocol.RepSuccess {
		return rep, mapRepError("BIND", rep.Response)
	}
	return rep, nil
}

// Bind is a convenience helper that performs both BIND steps.
func (c *Client) Bind(ctx context.Context, conn net.Conn, expect protocol.AddrSpec) (first protocol.Reply, second protocol.Reply, err error) {
	first, err = c.BindStart(ctx, conn, expect)
	if err != nil {
		return
	}
	second, err = c.BindWait(ctx, conn)
	return
}

// Hop describes a single SOCKS5 hop in a multi-hop chain.
// Address is the hop's SOCKS server address in "host:port" form.
// Creds and TLSConfig are optional per-hop settings.
type Hop struct {
	Address   string
	Creds     *Credentials
	TLSConfig *tls.Config
}

// DialChain dials the first hop and builds a multi-hop chain over a single stream,
// issuing CONNECT+Handshake for each subsequent hop, then CONNECT to the final target.
// The chain must contain at least one Hop (the first SOCKS server).
// dialTimeout controls the TCP dial to the first hop; per-request timeouts are controlled
// by the client's options (WithHandshakeTimeout/WithIOTimeout).
func (c *Client) DialChain(ctx context.Context, chain []Hop, finalTarget string, dialTimeout time.Duration) (net.Conn, error) {
	if len(chain) == 0 {
		return nil, errors.New("dialchain: empty chain")
	}

	conn, err := c.dialFirstHop(ctx, chain[0], dialTimeout)
	if err != nil {
		return nil, err
	}

	closeOnErr := func(e error) (net.Conn, error) {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, e
	}

	if len(chain) > 1 {
		nextConn, err := c.extendChain(ctx, conn, chain[1:])
		if err != nil {
			conn = nextConn
			return closeOnErr(err)
		}
		conn = nextConn
	}

	if finalTarget == "" {
		return conn, nil
	}

	if err := c.connectFinalTarget(ctx, conn, finalTarget); err != nil {
		return closeOnErr(err)
	}
	return conn, nil
}

func (c *Client) dialFirstHop(ctx context.Context, hop Hop, dialTimeout time.Duration) (net.Conn, error) {
	to := dialTimeout
	if to <= 0 {
		to = 5 * time.Second
	}

	dialCtx := ctx
	var cancel context.CancelFunc
	if to > 0 {
		if _, ok := ctx.Deadline(); !ok {
			dialCtx, cancel = context.WithTimeout(ctx, to)
		}
	}
	if cancel != nil {
		defer cancel()
	}

	d := c.dialer
	if d == nil {
		d = &net.Dialer{Timeout: to}
	}
	conn, err := d.DialContext(dialCtx, "tcp", hop.Address)
	if err != nil {
		return nil, err
	}

	cleanup := func(e error) (net.Conn, error) {
		_ = conn.Close()
		return nil, e
	}

	if hop.TLSConfig != nil {
		tconn := tls.Client(conn, hop.TLSConfig)
		if err := tconn.Handshake(); err != nil {
			return cleanup(err)
		}
		conn = tconn
	}

	if _, err := c.Handshake(ctx, conn, hop.Creds); err != nil {
		return cleanup(err)
	}

	return conn, nil
}

func (c *Client) extendChain(ctx context.Context, conn net.Conn, hops []Hop) (net.Conn, error) {
	current := conn
	for _, hop := range hops {
		dst, err := protocol.ParseAddrSpec(hop.Address)
		if err != nil {
			return current, err
		}
		if _, err = c.Connect(ctx, current, dst); err != nil {
			return current, err
		}
		if hop.TLSConfig != nil {
			tconn := tls.Client(current, hop.TLSConfig)
			if err := tconn.Handshake(); err != nil {
				return current, err
			}
			current = tconn
		}
		if _, err = c.Handshake(ctx, current, hop.Creds); err != nil {
			return current, err
		}
	}
	return current, nil
}

func (c *Client) connectFinalTarget(ctx context.Context, conn net.Conn, finalTarget string) error {
	dst, err := protocol.ParseAddrSpec(finalTarget)
	if err != nil {
		return err
	}
	_, err = c.Connect(ctx, conn, dst)
	return err
}

// UDPAssociate establishes a UDP ASSOCIATE on conn. It binds a local UDP
// socket (configurable via WithUDPLocalAddr) and advertises its address in the
// ASSOCIATE request. It returns the local UDP association and the server reply.
func (c *Client) UDPAssociate(ctx context.Context, conn net.Conn) (*UDPAssociation, protocol.Reply, error) {
	var rep protocol.Reply
	if conn == nil {
		return nil, rep, errors.New("nil connection")
	}

	// Bind local UDP first to include the actual local port in the request.
	laddr := c.udpLocalAddr
	if laddr == nil {
		laddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}
	pc, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, rep, fmt.Errorf("listen udp: %w", err)
	}

	// Build DstAddr from the local UDP socket address.
	la := pc.LocalAddr().(*net.UDPAddr)
	var atyp byte
	if la.IP.To4() != nil {
		atyp = protocol.ATYPIPv4
	} else {
		atyp = protocol.ATYPIPv6
	}
	req := protocol.Request{
		Version:  protocol.VersionSocks5,
		Command:  protocol.CommandAssociate,
		Reserved: 0,
		DstAddr:  protocol.AddrSpec{IP: la.IP, Port: la.Port, AddrType: atyp},
	}

	cl, dErr := c.applyDeadline(ctx, conn, c.ioTimeout)
	if dErr != nil {
		_ = pc.Close()
		return nil, rep, dErr
	}
	if cl != nil {
		defer cl()
	}

	if _, err = conn.Write(req.Bytes()); err != nil {
		_ = pc.Close()
		return nil, rep, fmt.Errorf("write ASSOCIATE: %w", err)
	}

	rep, err = protocol.ParseReply(conn)
	if err != nil {
		_ = pc.Close()
		return nil, rep, fmt.Errorf("read ASSOCIATE reply: %w", err)
	}
	if rep.Response != protocol.RepSuccess {
		_ = pc.Close()
		return nil, rep, mapRepError("ASSOCIATE", rep.Response)
	}

	// Build UDP relay address from BND.ADDR
	var relayIP net.IP
	if len(rep.BndAddr.IP) > 0 {
		relayIP = net.IP(rep.BndAddr.IP)
	} else {
		// Resolve FQDN if the server returned a domain (rare)
		ips, rerr := net.DefaultResolver.LookupIP(context.Background(), "ip", rep.BndAddr.FQDN)
		if rerr != nil || len(ips) == 0 {
			_ = pc.Close()
			if rerr != nil {
				return nil, rep, fmt.Errorf("resolve relay addr: %w", rerr)
			}
			return nil, rep, fmt.Errorf("resolve relay addr: no result for %s", rep.BndAddr.FQDN)
		}
		relayIP = ips[0]
	}
	relay := &net.UDPAddr{IP: relayIP, Port: rep.BndAddr.Port}

	assoc, aerr := cudp.NewAssociation(pc, relay,
		cudp.WithLogger(c.logger),
		cudp.WithKeepAlive(c.udpKeepAliveIntv, c.udpKeepAliveData),
	)
	if aerr != nil {
		_ = pc.Close()
		return nil, rep, aerr
	}
	return assoc, rep, nil
}

// Utility: apply combined deadline derived from ctx and fallback timeout.
func (c *Client) applyDeadline(ctx context.Context, conn net.Conn, fallback time.Duration) (clear func(), err error) {
	// prefer context deadline if present, otherwise fallback
	deadline := time.Time{}
	if t, ok := ctx.Deadline(); ok {
		deadline = t
	} else if fallback > 0 {
		deadline = time.Now().Add(fallback)
	}
	if !deadline.IsZero() {
		if err = conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
		return func() { _ = conn.SetDeadline(time.Time{}) }, nil
	}
	return nil, nil
}

func mapRepError(op string, code byte) error {
	var msg string
	switch code {
	case protocol.RepServerFailure:
		msg = "general server failure"
	case protocol.RepRuleFailure:
		msg = "rule failure"
	case protocol.RepNetworkUnreachable:
		msg = "network unreachable"
	case protocol.RepHostUnreachable:
		msg = "host unreachable"
	case protocol.RepConnectionRefused:
		msg = "connection refused"
	case protocol.RepTTLExpired:
		msg = "ttl expired / timeout"
	case protocol.RepCommandNotSupported:
		msg = "command not supported"
	case protocol.RepAddrTypeNotSupported:
		msg = "address type not supported"
	default:
		msg = fmt.Sprintf("unknown rep code %d", code)
	}
	return fmt.Errorf("%s failed: %s", op, msg)
}
