package socks5_test

import (
	"bytes"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"
	"testing"

	socks5 "github.com/AeonDave/go-s5"
	"github.com/AeonDave/go-s5/internal/protocol"

	"github.com/stretchr/testify/require"
)

type countingGPool struct{ n int32 }

func (p *countingGPool) Submit(f func()) error {
	atomic.AddInt32(&p.n, 1)
	go f()
	return nil
}

// Ensure goFunc uses the configured GPool (Submit gets called)
func Test_GPool_Submit_IsUsed(t *testing.T) {
	backend, stopBackend := startTCPBackend(t)
	defer stopBackend()

	var pool countingGPool
	listen, stop := startSocks5(t,
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		socks5.WithGPool(&pool),
	)
	defer stop()

	c, err := net.Dial("tcp", listen)
	require.NoError(t, err)
	defer func(c net.Conn) {
		_ = c.Close()
	}(c)

	// NoAuth
	_, _ = c.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	m := make([]byte, 2)
	_, err = io.ReadFull(c, m)
	require.NoError(t, err)

	// CONNECT to backend
	req := bytes.NewBuffer(nil)
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandConnect,
		DstAddr: protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: backend.Port, AddrType: protocol.ATYPIPv4}}
	req.Write(head.Bytes())
	req.WriteString("ping")
	_, _ = c.Write(req.Bytes())

	rep, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepSuccess), rep.Response)

	// Expect proxied response
	out := make([]byte, 4)
	_, err = io.ReadFull(c, out)
	require.NoError(t, err)

	// By now, ServeConn + two proxy copies should have submitted via the pool
	require.GreaterOrEqual(t, atomic.LoadInt32(&pool.n), int32(2))
}
