package socks5_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/AeonDave/go-s5/protocol"

	"github.com/stretchr/testify/require"
)

// Exercise the public re-export wrappers in protocol/api_protocol.go that are
// not covered by the internal protocol tests.
func TestAPIProtocolReExports(t *testing.T) {
	// ParseRequest
	req := protocol.Request{
		Version: protocol.VersionSocks5,
		Command: protocol.CommandConnect,
		DstAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 80, AddrType: protocol.ATYPIPv4},
	}
	parsedReq, err := protocol.ParseRequest(bytes.NewReader(req.Bytes()))
	require.NoError(t, err)
	require.Equal(t, byte(protocol.CommandConnect), parsedReq.Command)
	require.Equal(t, 80, parsedReq.DstAddr.Port)

	// ParseMethodRequest
	mreq := protocol.NewMethodRequest(protocol.VersionSocks5, []byte{protocol.MethodNoAuth})
	parsedM, err := protocol.ParseMethodRequest(bytes.NewReader(mreq.Bytes()))
	require.NoError(t, err)
	require.Equal(t, []byte{protocol.MethodNoAuth}, parsedM.Methods)

	// ParseUserPassRequest
	upr, err := protocol.NewUserPassRequest(protocol.UserPassAuthVersion, []byte("alice"), []byte("secret"))
	require.NoError(t, err)
	parsedUP, err := protocol.ParseUserPassRequest(bytes.NewReader(upr.Bytes()))
	require.NoError(t, err)
	require.Equal(t, []byte("alice"), parsedUP.User)
	require.Equal(t, []byte("secret"), parsedUP.Pass)

	// NewDatagram
	dg, err := protocol.NewDatagram("example.org:53", []byte("query"))
	require.NoError(t, err)
	require.Equal(t, "example.org", dg.DstAddr.FQDN)
	reparsed, err := protocol.ParseDatagram(dg.Bytes())
	require.NoError(t, err)
	require.Equal(t, []byte("query"), reparsed.Data)

	// NewDatagram error paths
	_, err = protocol.NewDatagram("no-port", nil)
	require.Error(t, err)
}
