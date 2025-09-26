package socks5_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"

	s5 "github.com/AeonDave/go-s5"
	"github.com/AeonDave/go-s5/auth"
	"github.com/AeonDave/go-s5/client"
	"github.com/AeonDave/go-s5/protocol"
	"github.com/stretchr/testify/require"
)

func startSocksServer(t *testing.T, opts ...s5.Option) (addr string, stop func()) {
	t.Helper()
	srv := s5.NewServer(opts...)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ln)
		close(done)
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Log("server did not stop in time")
		}
	}
}

func startTCPEcho(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func(conn net.Conn) {
					_ = conn.Close()
				}(conn)
				br := bufio.NewReader(conn)
				for {
					b, err := br.ReadBytes('\n')
					if err != nil {
						return
					}
					if _, err := conn.Write(b); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); <-stopped }
}

func startUDPEcho(t *testing.T) (addr string, stop func()) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		buf := make([]byte, 2048)
		for {
			n, ra, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(buf[:n], ra)
		}
	}()
	return pc.LocalAddr().String(), func() { _ = pc.Close(); <-stopped }
}

func TestClientHandshakeConnect_NoAuth(t *testing.T) {
	socksAddr, stopS := startSocksServer(t)
	defer stopS()

	echoAddr, stopE := startTCPEcho(t)
	defer stopE()

	conn, err := net.Dial("tcp", socksAddr)
	require.NoError(t, err)
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	cli := s5.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = cli.Handshake(ctx, conn, nil)
	require.NoError(t, err)

	dst, err := protocol.ParseAddrSpec(echoAddr)
	require.NoError(t, err)
	_, err = cli.Connect(ctx, conn, dst)
	require.NoError(t, err)

	// Echo
	_, err = conn.Write([]byte("hello\n"))
	require.NoError(t, err)
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "hello\n", line)
}

func TestClientHandshakeConnect_UserPass(t *testing.T) {
	socksAddr, stopS := startSocksServer(t, s5.WithCredential(auth.StaticCredentials{"u": "p"}))
	defer stopS()

	echoAddr, stopE := startTCPEcho(t)
	defer stopE()

	conn, err := net.Dial("tcp", socksAddr)
	require.NoError(t, err)
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	cli := s5.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = cli.Handshake(ctx, conn, &s5.Credentials{Username: "u", Password: "p"})
	require.NoError(t, err)

	dst, err := protocol.ParseAddrSpec(echoAddr)
	require.NoError(t, err)
	_, err = cli.Connect(ctx, conn, dst)
	require.NoError(t, err)

	_, err = conn.Write([]byte("auth-ok\n"))
	require.NoError(t, err)
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "auth-ok\n", line)
}

func TestClientBind(t *testing.T) {
	socksAddr, stopS := startSocksServer(t)
	defer stopS()

	conn, err := net.Dial("tcp", socksAddr)
	require.NoError(t, err)
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	cli := s5.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = cli.Handshake(ctx, conn, nil)
	require.NoError(t, err)

	// Expect any peer (0.0.0.0:0)
	expect := protocol.AddrSpec{IP: net.IPv4zero, Port: 0, AddrType: protocol.ATYPIPv4}

	first, err := cli.BindStart(ctx, conn, expect)
	require.NoError(t, err)

	// Remote peer connects to the server-provided bind addr
	var peerConn net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		var dErr error
		peerConn, dErr = net.Dial("tcp", first.BndAddr.String())
		if dErr != nil {
			return
		}
		// Peer: read PING then send PONG
		buf := make([]byte, 4)
		if _, dErr = io.ReadFull(peerConn, buf); dErr != nil {
			return
		}
		_, _ = peerConn.Write([]byte("PONG"))
	}()

	// Wait for acceptance
	_, err = cli.BindWait(ctx, conn)
	require.NoError(t, err)

	// Exchange
	_, err = conn.Write([]byte("PING"))
	require.NoError(t, err)
	rbuf := make([]byte, 4)
	_, err = io.ReadFull(conn, rbuf)
	require.NoError(t, err)
	require.Equal(t, []byte("PONG"), rbuf)

	<-done
	if peerConn != nil {
		_ = peerConn.Close()
	}
}

func TestClientUDPAssociate(t *testing.T) {
	socksAddr, stopS := startSocksServer(t)
	defer stopS()

	udpEchoAddr, stopU := startUDPEcho(t)
	defer stopU()

	conn, err := net.Dial("tcp", socksAddr)
	require.NoError(t, err)
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	cli := s5.NewClient()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = cli.Handshake(ctx, conn, nil)
	require.NoError(t, err)

	ua, _, err := cli.UDPAssociate(ctx, conn)
	require.NoError(t, err)
	defer func(ua *client.UDPAssociation) {
		_ = ua.Close()
	}(ua)

	dst, err := protocol.ParseAddrSpec(udpEchoAddr)
	require.NoError(t, err)

	payload := []byte("ping-udp")
	_, err = ua.WriteTo(dst, payload)
	require.NoError(t, err)

	buf := make([]byte, 64)
	n, gotDst, _, err := ua.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, dst.Address(), gotDst.Address())
	require.Equal(t, payload, buf[:n])
}
