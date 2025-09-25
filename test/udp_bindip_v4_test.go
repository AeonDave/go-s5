package socks5_test

import (
	"bytes"
	socks5 "go-s5"
	"go-s5/internal/protocol"
	"io"
	"log"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// Ensure UDP ASSOCIATE binds to provided IPv4 bind IP when enabled.
func TestUDP_Associate_BindIPv4Used(t *testing.T) {
	loc4 := net.ParseIP("127.0.0.1")
	listen, stop := startSocks5(t,
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		socks5.WithUseBindIpBaseResolveAsUdpAddr(true),
		socks5.WithBindIP(loc4),
	)
	defer stop()

	ctrl, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(ctrl net.Conn) {
		_ = ctrl.Close()
	}(ctrl)

	// NoAuth + ASSOCIATE
	req := bytes.NewBuffer(nil)
	req.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandAssociate,
		DstAddr: protocol.AddrSpec{IP: loc4, Port: 0, AddrType: protocol.ATYPIPv4}}
	req.Write(head.Bytes())
	_, _ = ctrl.Write(req.Bytes())
	// method
	m := make([]byte, 2)
	_, err = io.ReadFull(ctrl, m)
	require.NoError(t, err)
	rep, err := protocol.ParseReply(ctrl)
	require.NoError(t, err)

	require.Equal(t, byte(protocol.ATYPIPv4), rep.BndAddr.AddrType)
	// IP may be 0.0.0.0 on some stacks if bindIP ignored; assert equal when specified
	require.True(t, rep.BndAddr.IP.Equal(loc4))
}
