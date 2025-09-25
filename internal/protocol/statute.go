package protocol

import "errors"

const VersionSocks5 = 0x05

const (
	CommandConnect   = 0x01
	CommandBind      = 0x02
	CommandAssociate = 0x03
)

const (
	MethodNoAuth       = 0x00
	MethodGSSAPI       = 0x01 // Not supported
	MethodUserPassAuth = 0x02
	MethodNoAcceptable = 0xff
)

const (
	ATYPIPv4   = 0x01
	ATYPDomain = 0x03
	ATYPIPv6   = 0x04
)

const (
	RepSuccess uint8 = iota
	RepServerFailure
	RepRuleFailure
	RepNetworkUnreachable
	RepHostUnreachable
	RepConnectionRefused
	RepTTLExpired
	RepCommandNotSupported
	RepAddrTypeNotSupported
)

const (
	UserPassAuthVersion = 0x01
	AuthSuccess         = 0x00
	AuthFailure         = 0x01
)

var (
	ErrUnrecognizedAddrType = errors.New("unrecognized address type")
	ErrNotSupportVersion    = errors.New("unsupported version")
	ErrNotSupportMethod     = errors.New("unsupported method")
)
