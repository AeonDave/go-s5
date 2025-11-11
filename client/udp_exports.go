package client

import cudp "github.com/AeonDave/go-s5/client/udp"

// UDPAssociation re-exports the UDP association helper for backwards
// compatibility. New code can depend on client/udp directly.
type UDPAssociation = cudp.Association

// UDPAddr exposes the SOCKS-aware UDP address helper.
type UDPAddr = cudp.Addr

// ParseUDPAddr wraps udp.ParseAddr for callers rooted in the client package.
var ParseUDPAddr = cudp.ParseAddr
