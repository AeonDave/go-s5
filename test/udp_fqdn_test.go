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

	"github.com/AeonDave/go-s5/auth"
	"github.com/AeonDave/go-s5/internal/protocol"
	server "github.com/AeonDave/go-s5/server"

	"github.com/stretchr/testify/require"
)

// Ensure UDP ASSOCIATE handles FQDN in datagram
func TestUDP_FQDNTarget(t *testing.T) {
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
		server.WithAuthMethods([]auth.Authenticator{cator}),
		server.WithLogger(server.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)
	defer stop()

	ctrl, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(ctrl net.Conn) {
		_ = ctrl.Close()
	}(ctrl)

	req := bytes.NewBuffer(nil)
	req.Write([]byte{protocol.VersionSocks5, 2, protocol.MethodNoAuth, protocol.MethodUserPassAuth})
	up, err := protocol.NewUserPassRequest(protocol.UserPassAuthVersion, []byte("foo"), []byte("bar"))
	require.NoError(t, err)
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

	// client UDP socket
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: locIP, Port: 0})
	require.NoError(t, err)
	defer func(client *net.UDPConn) {
		_ = client.Close()
	}(client)

	// datagram to localhost (FQDN) -> upstream port
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(upstreamAddr.Port))
	msg := []byte{0, 0, 0, protocol.ATYPDomain, byte(len("localhost"))}
	msg = append(msg, []byte("localhost")...)
	msg = append(msg, pb...)
	msg = append(msg, []byte("ping")...)
	_, _ = client.WriteTo(msg, &net.UDPAddr{IP: locIP, Port: rep.BndAddr.Port})

	buf := make([]byte, 1024)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := client.ReadFrom(buf)
	_ = client.SetReadDeadline(time.Time{})
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), buf[n-4:n])
}

// Datagram with Frag != 0 must be dropped (no response)
func TestUDP_DropFragmented(t *testing.T) {
	locIP := net.ParseIP("127.0.0.1")
	listen, stop := startSocks5(t,
		server.WithLogger(server.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)
	defer stop()

	ctrl, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(ctrl net.Conn) {
		_ = ctrl.Close()
	}(ctrl)

	// handshake NoAuth + ASSOCIATE
	req := bytes.NewBuffer(nil)
	req.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	_, _ = ctrl.Write(req.Bytes())
	// method reply
	m := make([]byte, 2)
	_, err = io.ReadFull(ctrl, m)
	require.NoError(t, err)
	// ASSOCIATE
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandAssociate,
		DstAddr: protocol.AddrSpec{IP: locIP, Port: 0, AddrType: protocol.ATYPIPv4}}
	_, _ = ctrl.Write(head.Bytes())
	rep, err := protocol.ParseReply(ctrl)
	require.NoError(t, err)

	// UDP client
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: locIP, Port: 0})
	require.NoError(t, err)
	defer func(client *net.UDPConn) {
		_ = client.Close()
	}(client)

	// craft fragmented datagram to self (will be dropped)
	ipb := []byte{127, 0, 0, 1}
	pb := []byte{0, 80}
	msg := []byte{0, 0, 1 /*frag*/, protocol.ATYPIPv4}
	msg = append(msg, ipb...)
	msg = append(msg, pb...)
	msg = append(msg, []byte("ping")...)
	_, _ = client.WriteTo(msg, &net.UDPAddr{IP: locIP, Port: rep.BndAddr.Port})

	buf := make([]byte, 8)
	_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, _, err = client.ReadFrom(buf)
	require.Error(t, err) // timeout expected (no response)
}
