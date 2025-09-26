package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

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
}

// New creates a new Client.
func New(opts ...Option) *Client {
	c := &Client{
		handshakeTimeout: 5 * time.Second,
		ioTimeout:        10 * time.Second,
		methods:          nil,
		udpLocalAddr:     &net.UDPAddr{IP: net.IPv4zero, Port: 0},
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
		upr := protocol.NewUserPassRequest(protocol.UserPassAuthVersion, []byte(creds.Username), []byte(creds.Password))
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
	// 1) TCP dial to first hop
	to := dialTimeout
	if to <= 0 {
		to = 5 * time.Second
	}
	var dialCtx context.Context = ctx
	// apply a local timeout for the initial dial if ctx has no deadline
	if to > 0 {
		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			dialCtx, cancel = context.WithTimeout(ctx, to)
			defer cancel()
		}
	}
	d := c.dialer
	if d == nil {
		d = &net.Dialer{Timeout: to}
	}
	conn, err := d.DialContext(dialCtx, "tcp", chain[0].Address)
	if err != nil {
		return nil, err
	}
	closeOnErr := func(e error) (net.Conn, error) { _ = conn.Close(); return nil, e }

	// Optional TLS to first hop, then Handshake
	if tc := chain[0].TLSConfig; tc != nil {
		tconn := tls.Client(conn, tc)
		if err := tconn.Handshake(); err != nil {
			return closeOnErr(err)
		}
		conn = tconn
	}
	if _, err := c.Handshake(ctx, conn, chain[0].Creds); err != nil {
		return closeOnErr(err)
	}

	// 2) Intermediate hops
	for i := 1; i < len(chain); i++ {
		next := chain[i]
		dst, err := protocol.ParseAddrSpec(next.Address)
		if err != nil {
			return closeOnErr(err)
		}
		if _, err = c.Connect(ctx, conn, dst); err != nil {
			return closeOnErr(err)
		}
		if next.TLSConfig != nil {
			tconn := tls.Client(conn, next.TLSConfig)
			if err := tconn.Handshake(); err != nil {
				return closeOnErr(err)
			}
			conn = tconn
		}
		if _, err = c.Handshake(ctx, conn, next.Creds); err != nil {
			return closeOnErr(err)
		}
	}

	// 3) Final target CONNECT (optional): if finalTarget is empty, return positioned at last hop
	if finalTarget != "" {
		dst, err := protocol.ParseAddrSpec(finalTarget)
		if err != nil {
			return closeOnErr(err)
		}
		if _, err = c.Connect(ctx, conn, dst); err != nil {
			return closeOnErr(err)
		}
	}
	return conn, nil
}

// UDPAssociation represents an established UDP ASSOCIATE session.
// The TCP conn must be kept open for the lifetime of the association.
type UDPAssociation struct {
	// Conn is the local UDP socket used to send/receive encapsulated datagrams.
	Conn *net.UDPConn
	// RelayAddr is the SOCKS server's UDP relay endpoint returned in BND.ADDR.
	RelayAddr *net.UDPAddr
}

// Close closes the underlying UDP connection. It does not close the TCP conn.
func (u *UDPAssociation) Close() error {
	if u == nil || u.Conn == nil {
		return nil
	}
	return u.Conn.Close()
}

// WriteTo sends payload to the destination via the SOCKS UDP relay.
func (u *UDPAssociation) WriteTo(dst protocol.AddrSpec, payload []byte) (int, error) {
	if u == nil || u.Conn == nil || u.RelayAddr == nil {
		return 0, errors.New("invalid UDP association")
	}
	dg := protocol.Datagram{RSV: 0, Frag: 0, DstAddr: dst, Data: payload}
	return u.Conn.WriteToUDP(dg.Bytes(), u.RelayAddr)
}

// ReadFrom receives a datagram from the relay, returning the original
// destination address encoded by the server and the payload copied into buf.
func (u *UDPAssociation) ReadFrom(buf []byte) (n int, dst protocol.AddrSpec, from *net.UDPAddr, err error) {
	if u == nil || u.Conn == nil {
		err = errors.New("invalid UDP association")
		return
	}
	// Allocate a temporary buffer to accommodate headers.
	tmp := make([]byte, len(buf)+64)
	var rn int
	rn, from, err = u.Conn.ReadFromUDP(tmp)
	if err != nil {
		return
	}
	dg, perr := protocol.ParseDatagram(tmp[:rn])
	if perr != nil {
		err = perr
		return
	}
	if len(dg.Data) > len(buf) {
		err = io.ErrShortBuffer
		return
	}
	copy(buf, dg.Data)
	n = len(dg.Data)
	dst = dg.DstAddr
	return
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

	return &UDPAssociation{Conn: pc, RelayAddr: relay}, rep, nil
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
