package linkquality

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTrackerAggregatesMetrics(t *testing.T) {
	tracker := NewTracker(Metadata{Kind: EndpointSOCKS5, TLS: true, Notes: "chain hop"})

	tracker.RecordProbe(20*time.Millisecond, nil)
	tracker.RecordProbe(30*time.Millisecond, nil)
	tracker.RecordProbe(0, errors.New("timeout"))

	tracker.RecordThroughput(1024, time.Second)
	tracker.RecordThroughput(2048, 2*time.Second)

	tracker.MarkDown()
	time.Sleep(10 * time.Millisecond)
	tracker.MarkUp()

	info := tracker.ConnectionInfo()

	if info.Success != 2 || info.Failures != 1 {
		t.Fatalf("unexpected probe counts: %+v", info)
	}
	if info.RTT.Min == 0 || info.RTT.Max == 0 || info.RTT.Avg == 0 {
		t.Fatalf("missing rtt stats: %+v", info.RTT)
	}
	if info.Throughput.Samples != 2 {
		t.Fatalf("missing throughput samples: %+v", info.Throughput)
	}
	if info.UptimeRatio <= 0 || info.UptimeRatio > 1 {
		t.Fatalf("invalid uptime ratio: %f", info.UptimeRatio)
	}
	if info.Composite <= 0 {
		t.Fatalf("score should be positive, got %d", info.Composite)
	}
}

func TestProbeTCPUsesTracker(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var accepted int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&accepted, 1)
			_ = conn.Close()
		}
	}()

	tracker := NewTracker(Metadata{RemoteAddr: ln.Addr().String(), Kind: EndpointTCP})
	info, err := ProbeTCP(ln.Addr().String(), 3, 200*time.Millisecond, tracker)
	if err != nil {
		t.Fatalf("probe tcp: %v", err)
	}

	if info.Success == 0 || info.Probes != 3 {
		t.Fatalf("expected successful probes, got %+v", info)
	}
	if atomic.LoadInt32(&accepted) == 0 {
		t.Fatalf("listener did not see any dials")
	}
}

func TestProbeSOCKSHandshake(t *testing.T) {
	ctx := context.Background()
	tracker := NewTracker(Metadata{Kind: EndpointSOCKS5, TLS: false, Notes: "handshake"})

	info, err := ProbeSOCKSHandshake(ctx, func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}, tracker)
	if err != nil {
		t.Fatalf("probe handshake failed: %v", err)
	}

	if info.Success != 1 || info.Failures != 0 {
		t.Fatalf("unexpected probe result: %+v", info)
	}
	if info.Metadata.Kind != EndpointSOCKS5 {
		t.Fatalf("metadata kind mismatch: %+v", info.Metadata)
	}
}

func TestWrapConnIsTransparent(t *testing.T) {
	tracker := NewTracker(Metadata{Kind: EndpointTCP})
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	wrapped := WrapConn(client, tracker)
	msg := []byte("hello")

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, len(msg))
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("server read: %v", err)
		}
		if string(buf[:n]) != string(msg) {
			t.Fatalf("unexpected payload: %q", buf[:n])
		}
	}()

	if _, err := wrapped.Write(msg); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	<-done

	info := tracker.ConnectionInfo()
	if info.Throughput.Samples == 0 || info.Throughput.TotalBytes == 0 {
		t.Fatalf("throughput not recorded: %+v", info.Throughput)
	}
}

type closeWriterConn struct {
	net.Conn
	called bool
}

func (c *closeWriterConn) CloseWrite() error {
	c.called = true
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func TestWrapConnPreservesCloseWrite(t *testing.T) {
	tracker := NewTracker(Metadata{Kind: EndpointTCP})
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	cw := &closeWriterConn{Conn: client}
	wrapped := WrapConn(cw, tracker)

	halfCloser, ok := wrapped.(interface{ CloseWrite() error })
	require.True(t, ok, "wrapped connection should expose CloseWrite")
	require.NoError(t, halfCloser.CloseWrite())
	require.True(t, cw.called, "underlying CloseWrite should be invoked")
}
