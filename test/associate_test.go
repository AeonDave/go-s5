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

	s5 "github.com/AeonDave/go-s5"
	"github.com/AeonDave/go-s5/auth"
	"github.com/AeonDave/go-s5/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestSOCKS5_Associate(t *testing.T) {
	locIP := net.ParseIP("127.0.0.1")
	// upstream echo server over UDP
	serverAddr := &net.UDPAddr{IP: locIP, Port: 0}
	server, err := net.ListenUDP("udp", serverAddr)
	require.NoError(t, err)
	defer func(server *net.UDPConn) {
		_ = server.Close()
	}(server)
	// update with allocated port
	serverAddr = server.LocalAddr().(*net.UDPAddr)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, remote, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			if n > 0 {
				_, _ = server.WriteTo([]byte("pong"), remote)
			}
		}
	}()

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: locIP, Port: 0})
	require.NoError(t, err)
	defer func(client *net.UDPConn) {
		_ = client.Close()
	}(client)
	clientAddr := client.LocalAddr().(*net.UDPAddr)

	cator := auth.UserPassAuthenticator{Credentials: auth.StaticCredentials{"foo": "bar"}}
	listen, stop := startSocks5(t,
		s5.WithAuthMethods([]auth.Authenticator{cator}),
		s5.WithLogger(s5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
	)
	defer stop()

	conn, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	// handshake + userpass + ASSOCIATE
	req := bytes.NewBuffer(nil)
	req.Write([]byte{protocol.VersionSocks5, 2, protocol.MethodNoAuth, protocol.MethodUserPassAuth})
	up := protocol.NewUserPassRequest(protocol.UserPassAuthVersion, []byte("foo"), []byte("bar"))
	req.Write(up.Bytes())
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandAssociate, DstAddr: protocol.AddrSpec{IP: clientAddr.IP, Port: clientAddr.Port, AddrType: protocol.ATYPIPv4}}
	req.Write(head.Bytes())
	_, _ = conn.Write(req.Bytes())

	// method + auth status
	m := make([]byte, 2)
	_, err = io.ReadFull(conn, m)
	require.NoError(t, err)
	a := make([]byte, 2)
	_, err = io.ReadFull(conn, a)
	require.NoError(t, err)

	rep, err := protocol.ParseReply(conn)
	require.NoError(t, err)
	require.Equal(t, protocol.RepSuccess, rep.Response)

	// craft UDP datagram to upstream server routed via proxy bind
	ipb := serverAddr.IP.To4()
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(serverAddr.Port))
	msg := []byte{0, 0, 0, protocol.ATYPIPv4}
	msg = append(msg, ipb...)
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
