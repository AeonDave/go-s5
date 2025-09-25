package socks5_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"testing"
	"time"

	socks5 "github.com/AeonDave/go-s5"
	"github.com/AeonDave/go-s5/auth"
	"github.com/AeonDave/go-s5/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestUDP_Associate_LimitsAndIdleCleanup(t *testing.T) {
	locIP := net.ParseIP("127.0.0.1")
	upstream, err := net.ListenUDP("udp", &net.UDPAddr{IP: locIP, Port: 0})
	require.NoError(t, err)
	defer func(upstream *net.UDPConn) {
		_ = upstream.Close()
	}(upstream)
	upstreamAddr := upstream.LocalAddr().(*net.UDPAddr)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, r, err := upstream.ReadFrom(buf)
			if err != nil {
				return
			}
			if n > 0 {
				_, _ = upstream.WriteTo([]byte("pong"), r)
			}
		}
	}()

	cator := auth.UserPassAuthenticator{Credentials: auth.StaticCredentials{"foo": "bar"}}
	listen, stop := startSocks5(t,
		socks5.WithAuthMethods([]auth.Authenticator{cator}),
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		socks5.WithUDPAssociateLimits(1, 300*time.Millisecond),
	)
	defer stop()

	ctrl, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(ctrl net.Conn) {
		_ = ctrl.Close()
	}(ctrl)

	// handshake + userpass + ASSOCIATE
	req := bytes.NewBuffer(nil)
	req.Write([]byte{protocol.VersionSocks5, 2, protocol.MethodNoAuth, protocol.MethodUserPassAuth})
	up := protocol.NewUserPassRequest(protocol.UserPassAuthVersion, []byte("foo"), []byte("bar"))
	req.Write(up.Bytes())
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandAssociate,
		DstAddr: protocol.AddrSpec{IP: locIP, Port: 0, AddrType: protocol.ATYPIPv4}}
	req.Write(head.Bytes())
	_, _ = ctrl.Write(req.Bytes())
	// consume method+auth
	m := make([]byte, 2)
	_, err = io.ReadFull(ctrl, m)
	require.NoError(t, err)
	a := make([]byte, 2)
	_, err = io.ReadFull(ctrl, a)
	require.NoError(t, err)
	rep, err := protocol.ParseReply(ctrl)
	require.NoError(t, err)

	// two UDP clients with different source ports
	c1, err := net.ListenUDP("udp", &net.UDPAddr{IP: locIP, Port: 0})
	require.NoError(t, err)
	defer func(c1 *net.UDPConn) {
		_ = c1.Close()
	}(c1)
	c2, err := net.ListenUDP("udp", &net.UDPAddr{IP: locIP, Port: 0})
	require.NoError(t, err)
	defer func(c2 *net.UDPConn) {
		_ = c2.Close()
	}(c2)

	// helper to send a UDP datagram via proxy to upstream
	send := func(c *net.UDPConn) {
		pb := make([]byte, 2)
		binary.BigEndian.PutUint16(pb, uint16(upstreamAddr.Port))
		msg := []byte{0, 0, 0, protocol.ATYPIPv4}
		msg = append(msg, upstreamAddr.IP.To4()...)
		msg = append(msg, pb...)
		msg = append(msg, []byte("ping")...)
		_, _ = c.WriteTo(msg, &net.UDPAddr{IP: locIP, Port: rep.BndAddr.Port})
	}

	// First peer should work
	send(c1)
	buf := make([]byte, 16)
	_ = c1.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, _, err := c1.ReadFrom(buf)
	_ = c1.SetReadDeadline(time.Time{})
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), buf[n-4:n])

	// Second peer should be blocked due to maxPeers=1
	send(c2)
	_ = c2.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _, err = c2.ReadFrom(buf)
	_ = c2.SetReadDeadline(time.Time{})
	require.Error(t, err)

	// Wait for idle cleanup then try second peer again -> should succeed now
	time.Sleep(700 * time.Millisecond)
	send(c2)
	_ = c2.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, _, err = c2.ReadFrom(buf)
	_ = c2.SetReadDeadline(time.Time{})
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), buf[n-4:n])
}
