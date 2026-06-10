// Package protocol exposes the SOCKS5 (RFC 1928) wire primitives — method
// negotiation, requests, replies, user/pass sub-negotiation (RFC 1929) and
// UDP datagram encapsulation — re-exported from the internal implementation
// so applications can build and parse SOCKS5 messages directly.
package protocol

import (
	"io"

	ip "github.com/AeonDave/go-s5/internal/protocol"
)

// Constants
//
//goland:noinspection GoUnusedConst
const (
	VersionSocks5 = ip.VersionSocks5

	CommandConnect   = ip.CommandConnect
	CommandBind      = ip.CommandBind
	CommandAssociate = ip.CommandAssociate

	MethodNoAuth       = ip.MethodNoAuth
	MethodGSSAPI       = ip.MethodGSSAPI
	MethodUserPassAuth = ip.MethodUserPassAuth
	MethodNoAcceptable = ip.MethodNoAcceptable

	ATYPIPv4   = ip.ATYPIPv4
	ATYPDomain = ip.ATYPDomain
	ATYPIPv6   = ip.ATYPIPv6

	RepSuccess              = ip.RepSuccess
	RepServerFailure        = ip.RepServerFailure
	RepRuleFailure          = ip.RepRuleFailure
	RepNetworkUnreachable   = ip.RepNetworkUnreachable
	RepHostUnreachable      = ip.RepHostUnreachable
	RepConnectionRefused    = ip.RepConnectionRefused
	RepTTLExpired           = ip.RepTTLExpired
	RepCommandNotSupported  = ip.RepCommandNotSupported
	RepAddrTypeNotSupported = ip.RepAddrTypeNotSupported

	UserPassAuthVersion = ip.UserPassAuthVersion
	AuthSuccess         = ip.AuthSuccess
	AuthFailure         = ip.AuthFailure
)

// AddrSpec is a SOCKS5 address: an IPv4/IPv6 address or FQDN plus a port.
type AddrSpec = ip.AddrSpec

// Request is a SOCKS5 command request (CONNECT, BIND or UDP ASSOCIATE).
type Request = ip.Request

// Reply is a SOCKS5 command reply carrying the response code and bind address.
type Reply = ip.Reply

// MethodRequest is the client's method negotiation message.
type MethodRequest = ip.MethodRequest

// MethodReply is the server's method negotiation answer.
type MethodReply = ip.MethodReply

// Datagram is the UDP ASSOCIATE encapsulation header plus payload.
type Datagram = ip.Datagram

// Errors
//
//goland:noinspection GoUnusedGlobalVariable
var (
	ErrUnrecognizedAddrType = ip.ErrUnrecognizedAddrType
	ErrNotSupportVersion    = ip.ErrNotSupportVersion
	ErrNotSupportMethod     = ip.ErrNotSupportMethod
	ErrUserAuthFailed       = ip.ErrUserAuthFailed
	ErrNoSupportedAuth      = ip.ErrNoSupportedAuth
)

// ParseRequest reads a SOCKS5 command request from r.
func ParseRequest(r io.Reader) (Request, error) { return ip.ParseRequest(r) }

// ParseReply reads a SOCKS5 command reply from r.
func ParseReply(r io.Reader) (Reply, error) { return ip.ParseReply(r) }

// NewMethodRequest builds a method negotiation request advertising methods.
func NewMethodRequest(ver byte, methods []byte) MethodRequest {
	return ip.NewMethodRequest(ver, methods)
}

// ParseMethodRequest reads a method negotiation request from r.
func ParseMethodRequest(r io.Reader) (MethodRequest, error) { return ip.ParseMethodRequest(r) }

// ParseMethodReply reads a method negotiation reply from r.
func ParseMethodReply(r io.Reader) (MethodReply, error) { return ip.ParseMethodReply(r) }

// UserPassRequest is the RFC 1929 username/password authentication request.
type UserPassRequest = ip.UserPassRequest

// UserPassReply is the RFC 1929 authentication status reply.
type UserPassReply = ip.UserPassReply

// NewUserPassRequest builds an RFC 1929 authentication request. It fails if
// either credential exceeds 255 bytes.
func NewUserPassRequest(ver byte, user, pass []byte) (UserPassRequest, error) {
	return ip.NewUserPassRequest(ver, user, pass)
}

// ParseUserPassRequest reads an RFC 1929 authentication request from r.
func ParseUserPassRequest(r io.Reader) (UserPassRequest, error) { return ip.ParseUserPassRequest(r) }

// ParseUserPassReply reads an RFC 1929 authentication reply from r.
func ParseUserPassReply(r io.Reader) (UserPassReply, error) { return ip.ParseUserPassReply(r) }

// ParseAddrSpec parses a host:port string into an AddrSpec, classifying the
// host as IPv4, IPv6 or FQDN and validating the port range.
func ParseAddrSpec(addr string) (AddrSpec, error) { return ip.ParseAddrSpec(addr) }

// NewDatagram builds a UDP ASSOCIATE datagram for destAddr wrapping data.
func NewDatagram(destAddr string, data []byte) (Datagram, error) {
	return ip.NewDatagram(destAddr, data)
}

// ParseDatagram parses a UDP ASSOCIATE datagram from its wire encoding.
// The returned Datagram aliases b; copy it if b is reused.
func ParseDatagram(b []byte) (Datagram, error) { return ip.ParseDatagram(b) }
