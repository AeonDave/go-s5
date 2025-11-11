// Package udp exposes utilities for managing SOCKS5 UDP ASSOCIATE sessions
// negotiated by the client library. It offers high-level helpers to interact
// with the relay socket while preserving datagram semantics.
package udp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/AeonDave/go-s5/protocol"
)

// Association represents an established UDP ASSOCIATE session managed by the
// SOCKS5 client. It exposes helpers to interact with the relay and utilities
// to present the association as a standard net.PacketConn.
type Association struct {
	// Conn is the local UDP socket bound during the ASSOCIATE request.
	// It remains exported for callers that need low-level access to the
	// socket itself.
	Conn *net.UDPConn
	// RelayAddr is the UDP endpoint advertised by the SOCKS server.
	RelayAddr *net.UDPAddr
}

const datagramOverhead = 4 + 1 + 255 + 2 // RSV + FRAG + domain length + port

// NewAssociation constructs an Association from the negotiated UDP socket and
// relay address.
func NewAssociation(conn *net.UDPConn, relay *net.UDPAddr) (*Association, error) {
	if conn == nil {
		return nil, errors.New("nil UDP connection")
	}
	if relay == nil {
		return nil, errors.New("nil relay address")
	}
	return &Association{Conn: conn, RelayAddr: relay}, nil
}

// Close shuts down the underlying UDP socket. It does not touch the control
// TCP connection that negotiated the association.
func (a *Association) Close() error {
	if a == nil || a.Conn == nil {
		return nil
	}
	return a.Conn.Close()
}

// RelayAddress returns a defensive copy of the relay address advertised by the
// SOCKS server. Mutating the returned value does not affect the association.
func (a *Association) RelayAddress() *net.UDPAddr {
	if a == nil || a.RelayAddr == nil {
		return nil
	}
	cp := *a.RelayAddr
	if cp.IP != nil {
		cp.IP = append(net.IP(nil), cp.IP...)
	}
	return &cp
}

// LocalAddr exposes the address of the local UDP socket used for the
// association.
func (a *Association) LocalAddr() net.Addr {
	if a == nil || a.Conn == nil {
		return nil
	}
	return a.Conn.LocalAddr()
}

// SetDeadline applies a deadline to the underlying UDP socket.
func (a *Association) SetDeadline(t time.Time) error {
	if a == nil || a.Conn == nil {
		return errors.New("invalid UDP association")
	}
	return a.Conn.SetDeadline(t)
}

// SetReadDeadline applies a read deadline to the underlying UDP socket.
func (a *Association) SetReadDeadline(t time.Time) error {
	if a == nil || a.Conn == nil {
		return errors.New("invalid UDP association")
	}
	return a.Conn.SetReadDeadline(t)
}

// SetWriteDeadline applies a write deadline to the underlying UDP socket.
func (a *Association) SetWriteDeadline(t time.Time) error {
	if a == nil || a.Conn == nil {
		return errors.New("invalid UDP association")
	}
	return a.Conn.SetWriteDeadline(t)
}

// WriteTo sends payload to the destination through the SOCKS UDP relay.
func (a *Association) WriteTo(dst protocol.AddrSpec, payload []byte) (int, error) {
	if a == nil || a.Conn == nil || a.RelayAddr == nil {
		return 0, errors.New("invalid UDP association")
	}
	dg := protocol.Datagram{RSV: 0, Frag: 0, DstAddr: dst, Data: payload}
	return a.Conn.WriteToUDP(dg.Bytes(), a.RelayAddr)
}

// WriteToAddr is a convenience wrapper around WriteTo that accepts a
// host:port string and handles the AddrSpec encoding.
func (a *Association) WriteToAddr(address string, payload []byte) (int, error) {
	spec, err := protocol.ParseAddrSpec(address)
	if err != nil {
		return 0, fmt.Errorf("parse address: %w", err)
	}
	return a.WriteTo(spec, payload)
}

// ReadFrom receives a datagram from the relay, returning the original
// destination address encoded by the server and the payload copied into buf.
func (a *Association) ReadFrom(buf []byte) (n int, dst protocol.AddrSpec, from *net.UDPAddr, err error) {
	if a == nil || a.Conn == nil {
		err = errors.New("invalid UDP association")
		return
	}
	tmp := make([]byte, len(buf)+datagramOverhead)
	var rn int
	rn, from, err = a.Conn.ReadFromUDP(tmp)
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

// PacketConn exposes the UDP association as a net.PacketConn implementation
// that automatically handles SOCKS5 datagram encapsulation.
func (a *Association) PacketConn() net.PacketConn {
	return &relayPacketConn{assoc: a}
}

// Addr is a net.Addr implementation backed by a SOCKS5 AddrSpec. It allows
// callers to address UDP destinations that are not representable as *net.UDPAddr
// (for example, FQDN endpoints).
type Addr struct {
	AddrSpec protocol.AddrSpec
}

// Network implements net.Addr.
func (a Addr) Network() string { return "socks5+udp" }

// String implements net.Addr.
func (a Addr) String() string { return a.AddrSpec.String() }

// ParseAddr parses host:port into an Addr using SOCKS5 address rules.
func ParseAddr(address string) (Addr, error) {
	spec, err := protocol.ParseAddrSpec(address)
	if err != nil {
		return Addr{}, err
	}
	return Addr{AddrSpec: spec}, nil
}

type relayPacketConn struct {
	assoc *Association
}

func (r *relayPacketConn) ensureAssoc() error {
	if r == nil || r.assoc == nil || r.assoc.Conn == nil {
		return errors.New("invalid UDP association")
	}
	return nil
}

func (r *relayPacketConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	if err = r.ensureAssoc(); err != nil {
		return 0, nil, err
	}
	n, spec, _, err := r.assoc.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}
	return n, Addr{AddrSpec: spec}, nil
}

func (r *relayPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if err := r.ensureAssoc(); err != nil {
		return 0, err
	}
	spec, err := addrSpecFromNetAddr(addr)
	if err != nil {
		return 0, err
	}
	return r.assoc.WriteTo(spec, b)
}

func (r *relayPacketConn) Close() error {
	if r == nil || r.assoc == nil {
		return nil
	}
	return r.assoc.Close()
}

func (r *relayPacketConn) LocalAddr() net.Addr {
	if r == nil || r.assoc == nil {
		return nil
	}
	return r.assoc.LocalAddr()
}

func (r *relayPacketConn) SetDeadline(t time.Time) error {
	if err := r.ensureAssoc(); err != nil {
		return err
	}
	return r.assoc.SetDeadline(t)
}

func (r *relayPacketConn) SetReadDeadline(t time.Time) error {
	if err := r.ensureAssoc(); err != nil {
		return err
	}
	return r.assoc.SetReadDeadline(t)
}

func (r *relayPacketConn) SetWriteDeadline(t time.Time) error {
	if err := r.ensureAssoc(); err != nil {
		return err
	}
	return r.assoc.SetWriteDeadline(t)
}

func addrSpecFromNetAddr(addr net.Addr) (protocol.AddrSpec, error) {
	switch v := addr.(type) {
	case Addr:
		return v.AddrSpec, nil
	case *Addr:
		if v == nil {
			return protocol.AddrSpec{}, errors.New("nil UDP addr")
		}
		return v.AddrSpec, nil
	case *net.UDPAddr:
		if v == nil {
			return protocol.AddrSpec{}, errors.New("nil UDP addr")
		}
		spec := protocol.AddrSpec{IP: append(net.IP(nil), v.IP...), Port: v.Port}
		if v.IP.To4() != nil {
			spec.AddrType = protocol.ATYPIPv4
		} else {
			spec.AddrType = protocol.ATYPIPv6
		}
		return spec, nil
	default:
		return protocol.AddrSpec{}, fmt.Errorf("unsupported address type %T", addr)
	}
}
