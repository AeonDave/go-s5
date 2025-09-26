package protocol

// This package re-exports the SOCKS5 wire protocol primitives from the
// internal/protocol package so that external clients can build requests
// and parse replies without depending on internal paths.

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

// Types
type (
	AddrSpec      = ip.AddrSpec
	Request       = ip.Request
	Reply         = ip.Reply
	MethodRequest = ip.MethodRequest
	MethodReply   = ip.MethodReply
	Datagram      = ip.Datagram
)

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

// ParseRequest Request helpers
func ParseRequest(r io.Reader) (Request, error) { return ip.ParseRequest(r) }

// ParseReply Reply helpers
func ParseReply(r io.Reader) (Reply, error) { return ip.ParseReply(r) }

// NewMethodRequest Method negotiation helpers
func NewMethodRequest(ver byte, methods []byte) MethodRequest {
	return ip.NewMethodRequest(ver, methods)
}
func ParseMethodRequest(r io.Reader) (MethodRequest, error) { return ip.ParseMethodRequest(r) }
func ParseMethodReply(r io.Reader) (MethodReply, error)     { return ip.ParseMethodReply(r) }

// Username/Password sub-negotiation
type (
	UserPassRequest = ip.UserPassRequest
	UserPassReply   = ip.UserPassReply
)

func NewUserPassRequest(ver byte, user, pass []byte) UserPassRequest {
	return ip.NewUserPassRequest(ver, user, pass)
}
func ParseUserPassRequest(r io.Reader) (UserPassRequest, error) { return ip.ParseUserPassRequest(r) }
func ParseUserPassReply(r io.Reader) (UserPassReply, error)     { return ip.ParseUserPassReply(r) }

// ParseAddrSpec AddrSpec helpers
func ParseAddrSpec(addr string) (AddrSpec, error) { return ip.ParseAddrSpec(addr) }

// NewDatagram Datagram helpers
func NewDatagram(destAddr string, data []byte) (Datagram, error) {
	return ip.NewDatagram(destAddr, data)
}
func ParseDatagram(b []byte) (Datagram, error) { return ip.ParseDatagram(b) }

// Methods Header() and Bytes() are available on Datagram via type alias.
