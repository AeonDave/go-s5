package socks5_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	ctcp "github.com/AeonDave/go-s5/client/tcp"

	"github.com/stretchr/testify/require"
)

func TestTCPStream_NilConn(t *testing.T) {
	_, err := ctcp.NewStream(nil)
	require.Error(t, err)
}

func TestTCPStream_NilReceiverSafety(t *testing.T) {
	var s *ctcp.Stream
	require.Nil(t, s.Conn())
	require.NoError(t, s.Close())
	require.Nil(t, s.LocalAddr())
	require.Nil(t, s.RemoteAddr())
	require.Error(t, s.SetDeadline(time.Now()))
	require.Error(t, s.SetReadDeadline(time.Now()))
	require.Error(t, s.SetWriteDeadline(time.Now()))
	_, err := s.Write([]byte("x"))
	require.Error(t, err)
	require.Error(t, s.WriteAll([]byte("x")))
	_, err = s.WriteString("x")
	require.Error(t, err)
	_, err = s.Read(make([]byte, 1))
	require.Error(t, err)
	require.Error(t, s.ReadFull(make([]byte, 1)))
	_, err = s.CopyTo(&bytes.Buffer{})
	require.Error(t, err)
	_, err = s.CopyFrom(&bytes.Buffer{})
	require.Error(t, err)
	require.Error(t, s.Relay(t.Context(), nil))
}

func TestTCPStream_ReadWriteAndDeadlines(t *testing.T) {
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	s, err := ctcp.NewStream(a,
		ctcp.WithRelayBufferSize(8*1024),
		ctcp.WithRelayBufferSize(0), // invalid size falls back to default
		ctcp.WithRelayActivityTimeout(time.Second),
		nil, // nil options are skipped
	)
	require.NoError(t, err)

	require.Same(t, a, s.Conn())
	require.NotNil(t, s.LocalAddr())
	require.NotNil(t, s.RemoteAddr())

	require.NoError(t, s.SetDeadline(time.Now().Add(time.Second)))
	require.NoError(t, s.SetReadDeadline(time.Now().Add(time.Second)))
	require.NoError(t, s.SetWriteDeadline(time.Now().Add(time.Second)))
	require.NoError(t, s.SetDeadline(time.Time{}))

	// Write + Read roundtrip over the pipe.
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		buf := make([]byte, 5)
		if _, err := b.Read(buf); err != nil {
			return
		}
		_, _ = b.Write(buf)
	}()

	n, err := s.Write([]byte("hello"))
	require.NoError(t, err)
	require.Equal(t, 5, n)

	got := make([]byte, 5)
	_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = s.Read(got)
	require.NoError(t, err)
	require.Equal(t, "hello", string(got[:n]))
	<-echoDone

	// CopyTo with nil destination must fail fast.
	_, err = s.CopyTo(nil)
	require.Error(t, err)
	_, err = s.CopyFrom(nil)
	require.Error(t, err)
}
