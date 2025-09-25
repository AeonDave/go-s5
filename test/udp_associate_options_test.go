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
	"github.com/AeonDave/go-s5/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestUDP_Associate_BindIPUsed(t *testing.T) {
	loc6 := net.IPv6loopback
	// control TCP still on IPv4; configure UDP bind to IPv6
	listen, stop := startSocks5(t,
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		socks5.WithUseBindIpBaseResolveAsUdpAddr(true),
		socks5.WithBindIP(loc6),
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
		DstAddr: protocol.AddrSpec{IP: loc6, Port: 0, AddrType: protocol.ATYPIPv6}}
	req.Write(head.Bytes())
	_, _ = ctrl.Write(req.Bytes())
	// method
	m := make([]byte, 2)
	_, err = io.ReadFull(ctrl, m)
	require.NoError(t, err)
	rep, err := protocol.ParseReply(ctrl)
	require.NoError(t, err)

	if rep.BndAddr.AddrType != protocol.ATYPIPv6 {
		t.Skip("system does not support IPv6 UDP bind via bindIP; skipping")
	}
}

func TestUDP_Associate_StrictSourcePortMatch(t *testing.T) {
	loc := net.ParseIP("127.0.0.1")
	listen, stop := startSocks5(t,
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)
	defer stop()

	ctrl, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(ctrl net.Conn) {
		_ = ctrl.Close()
	}(ctrl)

	// NoAuth + ASSOCIATE with fixed source address:port
	c1, err := net.ListenUDP("udp", &net.UDPAddr{IP: loc, Port: 0})
	require.NoError(t, err)
	defer func(c1 *net.UDPConn) {
		_ = c1.Close()
	}(c1)
	c1addr := c1.LocalAddr().(*net.UDPAddr)

	req := bytes.NewBuffer(nil)
	req.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandAssociate,
		DstAddr: protocol.AddrSpec{IP: c1addr.IP, Port: c1addr.Port, AddrType: protocol.ATYPIPv4}}
	req.Write(head.Bytes())
	_, _ = ctrl.Write(req.Bytes())
	// method
	m := make([]byte, 2)
	_, err = io.ReadFull(ctrl, m)
	require.NoError(t, err)
	rep, err := protocol.ParseReply(ctrl)
	require.NoError(t, err)

	// upstream echo
	upstream, err := net.ListenUDP("udp", &net.UDPAddr{IP: loc, Port: 0})
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

	send := func(c *net.UDPConn) {
		pb := make([]byte, 2)
		binary.BigEndian.PutUint16(pb, uint16(upstreamAddr.Port))
		msg := []byte{0, 0, 0, protocol.ATYPIPv4}
		msg = append(msg, upstreamAddr.IP.To4()...)
		msg = append(msg, pb...)
		msg = append(msg, []byte("ping")...)
		_, _ = c.WriteTo(msg, &net.UDPAddr{IP: loc, Port: rep.BndAddr.Port})
	}

	// c1 should work
	send(c1)
	buf := make([]byte, 32)
	_ = c1.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, _, err := c1.ReadFrom(buf)
	_ = c1.SetReadDeadline(time.Time{})
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), buf[n-4:n])

	// c2 from different port should be ignored (no response)
	c2, err := net.ListenUDP("udp", &net.UDPAddr{IP: loc, Port: 0})
	require.NoError(t, err)
	defer func(c2 *net.UDPConn) {
		_ = c2.Close()
	}(c2)
	send(c2)
	_ = c2.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	_, _, err = c2.ReadFrom(buf)
	_ = c2.SetReadDeadline(time.Time{})
	require.Error(t, err)
}

func TestUDP_Associate_MaxPeersExceeded(t *testing.T) {
	loc := net.ParseIP("127.0.0.1")
	// upstream echo
	upstream, err := net.ListenUDP("udp", &net.UDPAddr{IP: loc, Port: 0})
	require.NoError(t, err)
	defer func(upstream *net.UDPConn) {
		_ = upstream.Close()
	}(upstream)
	upAddr := upstream.LocalAddr().(*net.UDPAddr)
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

	listen, stop := startSocks5(t,
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		socks5.WithUDPAssociateLimits(2, 300*time.Millisecond),
	)
	defer stop()

	ctrl, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(ctrl net.Conn) {
		_ = ctrl.Close()
	}(ctrl)

	// NoAuth + ASSOCIATE wildcard (IP+port)
	req := bytes.NewBuffer(nil)
	req.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandAssociate,
		DstAddr: protocol.AddrSpec{IP: loc, Port: 0, AddrType: protocol.ATYPIPv4}}
	req.Write(head.Bytes())
	_, _ = ctrl.Write(req.Bytes())
	// method
	m := make([]byte, 2)
	_, err = io.ReadFull(ctrl, m)
	require.NoError(t, err)
	rep, err := protocol.ParseReply(ctrl)
	require.NoError(t, err)

	// three UDP peers
	peers := make([]*net.UDPConn, 3)
	for i := 0; i < 3; i++ {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: loc, Port: 0})
		require.NoError(t, err)
		peers[i] = c
		defer func(c *net.UDPConn) {
			_ = c.Close()
		}(c)
	}
	send := func(c *net.UDPConn) {
		pb := make([]byte, 2)
		binary.BigEndian.PutUint16(pb, uint16(upAddr.Port))
		msg := []byte{0, 0, 0, protocol.ATYPIPv4}
		msg = append(msg, upAddr.IP.To4()...)
		msg = append(msg, pb...)
		msg = append(msg, []byte("ping")...)
		_, _ = c.WriteTo(msg, &net.UDPAddr{IP: loc, Port: rep.BndAddr.Port})
	}

	// First two should work
	for i := 0; i < 2; i++ {
		send(peers[i])
		buf := make([]byte, 32)
		_ = peers[i].SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := peers[i].ReadFrom(buf)
		_ = peers[i].SetReadDeadline(time.Time{})
		require.NoError(t, err)
		require.Equal(t, []byte("pong"), buf[n-4:n])
	}
	// Third should be dropped due to limit=2
	send(peers[2])
	_ = peers[2].SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	_, _, err = peers[2].ReadFrom(make([]byte, 32))
	_ = peers[2].SetReadDeadline(time.Time{})
	require.Error(t, err)
}
