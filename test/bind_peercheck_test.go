package socks5_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"

	socks5 "github.com/AeonDave/go-s5"
	"github.com/AeonDave/go-s5/internal/protocol"

	"github.com/stretchr/testify/require"
)

// If peerCheckIPOnly=false and request specifies a port, peers with mismatched port are rejected.
func TestBIND_PeerPortMismatch_ResultsInTTLExpired(t *testing.T) {
	listen, stop := startSocks5(t,
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		socks5.WithBindAcceptTimeout(150*time.Millisecond),
		socks5.WithBindPeerCheckIPOnly(false),
	)
	defer stop()

	c, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(c net.Conn) {
		_ = c.Close()
	}(c)

	// handshake: NoAuth
	_, _ = c.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	m := make([]byte, 2)
	_, err = io.ReadFull(c, m)
	require.NoError(t, err)

	// BIND expecting peer port 1 (unlikely)
	req := bytes.NewBuffer(nil)
	req.Write((protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandBind,
		DstAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 1, AddrType: protocol.ATYPIPv4}}).Bytes())
	_, _ = c.Write(req.Bytes())

	rep1, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepSuccess), rep1.Response)

	// Connect from mismatched port (ephemeral) should be rejected and accept should continue
	peer, err := net.Dial("tcp", net.JoinHostPort(rep1.BndAddr.IP.String(), fmt.Sprintf("%d", rep1.BndAddr.Port)))
	if err == nil {
		_ = peer.Close()
	}

	// Expect TTLExpired as no matching peer arrives
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	rep2, err := protocol.ParseReply(c)
	_ = c.SetReadDeadline(time.Time{})
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepTTLExpired), rep2.Response)
}
