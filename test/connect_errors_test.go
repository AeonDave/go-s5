package socks5_test

import (
	"bytes"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"

	socks5 "github.com/AeonDave/go-s5"
	"github.com/AeonDave/go-s5/internal/protocol"
	"github.com/AeonDave/go-s5/rules"

	"github.com/stretchr/testify/require"
)

// Connecting to an unused port should yield RepConnectionRefused
func TestCONNECT_ConnectionRefused(t *testing.T) {
	listen, stop := startSocks5(t,
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)
	defer stop()

	c, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(c net.Conn) {
		_ = c.Close()
	}(c)

	// handshake: offer NoAuth only
	_, _ = c.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	// read method selection
	m := make([]byte, 2)
	_, err = io.ReadFull(c, m)
	require.NoError(t, err)

	// build CONNECT to an unused port (loopback high port unlikely in use)
	// try to find an unused port by listening and closing
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	_ = l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	// after closing, dialing should refuse
	req := bytes.NewBuffer(nil)
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandConnect,
		DstAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: port, AddrType: protocol.ATYPIPv4}}
	req.Write(head.Bytes())
	_, _ = c.Write(req.Bytes())

	rep, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepConnectionRefused), rep.Response)
}

// RuleSet denies CONNECT should yield RepRuleFailure
func TestCONNECT_RuleBlocked(t *testing.T) {
	listen, stop := startSocks5(t,
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		socks5.WithRule(rules.NewPermitNone()),
	)
	defer stop()

	c, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(c net.Conn) {
		_ = c.Close()
	}(c)

	// handshake: offer NoAuth only
	_, _ = c.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	// read method selection
	m := make([]byte, 2)
	_, err = io.ReadFull(c, m)
	require.NoError(t, err)

	// build CONNECT anywhere
	req := bytes.NewBuffer(nil)
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandConnect,
		DstAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 1, AddrType: protocol.ATYPIPv4}}
	req.Write(head.Bytes())
	_, _ = c.Write(req.Bytes())

	// server should reject per rules before dialing
	rep, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepRuleFailure), rep.Response)
	_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = c.Read(make([]byte, 1))
}
