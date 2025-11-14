package socks5_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	client "github.com/AeonDave/go-s5/client"
	ctcp "github.com/AeonDave/go-s5/client/tcp"
	"github.com/AeonDave/go-s5/protocol"

	"github.com/stretchr/testify/require"
)

func TestClientConnectStreamHelpers(t *testing.T) {
	echoAddr, stopEcho := startTCPEcho(t)
	defer stopEcho()

	socksAddr, stopS := startSocksServer(t)
	defer stopS()

	conn, err := net.Dial("tcp", socksAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	cli := client.New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	_, err = cli.Handshake(ctx, conn, nil)
	require.NoError(t, err)

	dst, err := protocol.ParseAddrSpec(echoAddr)
	require.NoError(t, err)

	stream, _, err := cli.ConnectStream(ctx, conn, dst)
	require.NoError(t, err)
	t.Cleanup(func() { _ = stream.Close() })

	payload := "hello stream\n"
	n, err := stream.WriteString(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)

	buf := make([]byte, len(payload))
	require.NoError(t, stream.ReadFull(buf))
	require.Equal(t, payload, string(buf))

	require.NotNil(t, stream.LocalAddr())
	require.NotNil(t, stream.RemoteAddr())

	second := []byte("second line\n")
	require.NoError(t, stream.WriteAll(second))

	buf2 := make([]byte, len(second))
	require.NoError(t, stream.ReadFull(buf2))
	require.Equal(t, second, buf2)

	_, err = stream.CopyFrom(strings.NewReader("copy me\n"))
	require.NoError(t, err)

	buf3 := make([]byte, len("copy me\n"))
	require.NoError(t, stream.ReadFull(buf3))
	require.Equal(t, "copy me\n", string(buf3))
}

func TestTCPStreamRelayAndValidation(t *testing.T) {
	_, err := client.NewTCPStream(nil)
	require.Error(t, err)

	leftA, leftB := net.Pipe()
	rightA, rightB := net.Pipe()

	stream, err := ctcp.NewStream(leftA)
	require.NoError(t, err)
	t.Cleanup(func() { _ = stream.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	relayDone := make(chan error, 1)
	go func() {
		relayDone <- stream.Relay(ctx, rightA)
	}()

	defer func() {
		_ = leftB.Close()
		_ = rightB.Close()
	}()

	msg := []byte("left-to-right")
	_, err = leftB.Write(msg)
	require.NoError(t, err)

	mirrored := make([]byte, len(msg))
	_, err = io.ReadFull(rightB, mirrored)
	require.NoError(t, err)
	require.Equal(t, msg, mirrored)

	reverse := []byte("right-to-left")
	_, err = rightB.Write(reverse)
	require.NoError(t, err)

	mirroredBack := make([]byte, len(reverse))
	_, err = io.ReadFull(leftB, mirroredBack)
	require.NoError(t, err)
	require.Equal(t, reverse, mirroredBack)

	cancel()
	require.Eventually(t, func() bool { return len(relayDone) > 0 }, time.Second, 50*time.Millisecond)

	err = <-relayDone
	require.ErrorIs(t, err, context.Canceled)
}

func TestTCPStreamCopyValidation(t *testing.T) {
	a, b := net.Pipe()
	stream, err := ctcp.NewStream(a)
	require.NoError(t, err)
	defer func() {
		_ = stream.Close()
		_ = b.Close()
	}()

	_, err = stream.CopyTo(nil)
	require.Error(t, err)

	_, err = stream.CopyFrom(nil)
	require.Error(t, err)

	go func() {
		defer b.Close()
		_, _ = b.Write([]byte("payload"))
	}()

	var buf bytes.Buffer
	n, err := stream.CopyTo(&buf)
	require.NoError(t, err)
	require.Equal(t, int64(len("payload")), n)
	require.Equal(t, "payload", buf.String())
}
