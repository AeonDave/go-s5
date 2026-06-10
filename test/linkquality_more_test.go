package socks5_test

import (
	"net"
	"testing"
	"time"

	"github.com/AeonDave/go-s5/linkquality"

	"github.com/stretchr/testify/require"
)

func TestLinkQuality_ScoreAndState(t *testing.T) {
	tr := linkquality.NewTracker(linkquality.Metadata{Name: "test", Kind: linkquality.EndpointTCP})

	tr.RecordProbe(10*time.Millisecond, nil)
	tr.RecordProbe(20*time.Millisecond, nil)
	tr.RecordThroughput(64*1024, 100*time.Millisecond)
	tr.RecordThroughput(0, time.Second) // ignored: zero bytes

	score := tr.Score()
	require.GreaterOrEqual(t, score, 0)
	require.LessOrEqual(t, score, 100)

	tr.MarkDown()
	tr.MarkUp()
	info := tr.ConnectionInfo()
	require.Equal(t, 2, info.Probes)
	require.Equal(t, 2, info.Success)
	require.Positive(t, info.RTT.Avg)
	require.Positive(t, info.Throughput.TotalBytes)
}

func TestLinkQuality_WrapConnNilCases(t *testing.T) {
	require.Nil(t, linkquality.WrapConn(nil, nil))

	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	// nil tracker allocates a default one; the wrapper must still pass traffic.
	wrapped := linkquality.WrapConn(a, nil)
	require.NotNil(t, wrapped)
}

func TestLinkQuality_MeasuredConnReadWriteAndHalfClose(t *testing.T) {
	// Use a real TCP pair so CloseRead/CloseWrite are available underneath.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	srv := <-accepted
	t.Cleanup(func() { _ = srv.Close() })

	tr := linkquality.NewTracker(linkquality.Metadata{Kind: linkquality.EndpointTCP})
	conn := linkquality.WrapConn(raw, tr)

	// Write through the wrapper, echo from the server side, read back.
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = srv.Read(buf)
	require.NoError(t, err)
	_, err = srv.Write([]byte("pong"))
	require.NoError(t, err)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "pong", string(buf[:n]))

	// Throughput must have been recorded passively.
	info := tr.ConnectionInfo()
	require.Positive(t, info.Throughput.TotalBytes)

	// Half-close passthrough.
	cw, ok := conn.(interface{ CloseWrite() error })
	require.True(t, ok)
	require.NoError(t, cw.CloseWrite())
	cr, ok := conn.(interface{ CloseRead() error })
	require.True(t, ok)
	require.NoError(t, cr.CloseRead())
}
