package socks5_test

import (
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cudp "github.com/AeonDave/go-s5/client/udp"
	"github.com/AeonDave/go-s5/protocol"

	"github.com/stretchr/testify/require"
)

func TestUDPAssociationKeepAlive(t *testing.T) {
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = relay.Close() })

	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = local.Close() })

	interval := 20 * time.Millisecond
	assoc, err := cudp.NewAssociation(local, relay.LocalAddr().(*net.UDPAddr),
		cudp.WithKeepAlive(interval, []byte{0xAA}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = assoc.Close() })

	buf := make([]byte, 1)
	require.Eventually(t, func() bool {
		_ = relay.SetReadDeadline(time.Now().Add(interval))
		_, _, err := relay.ReadFromUDP(buf)
		return err == nil
	}, time.Second, interval)

	require.NoError(t, assoc.Close())
	_ = relay.SetReadDeadline(time.Now().Add(2 * interval))
	if _, _, err := relay.ReadFromUDP(buf); err == nil {
		t.Fatalf("unexpected keep-alive after close")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("unexpected error after close: %v", err)
	}
}

func TestUDPAssociationReadFromReusesBuffer(t *testing.T) {
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = relay.Close() })

	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	t.Cleanup(func() { _ = local.Close() })

	oldGC := debug.SetGCPercent(-1)
	t.Cleanup(func() { debug.SetGCPercent(oldGC) })

	var newCalls int32
	pool := &sync.Pool{New: func() any {
		atomic.AddInt32(&newCalls, 1)
		return make([]byte, 4096)
	}}

	assoc, err := cudp.NewAssociation(local, relay.LocalAddr().(*net.UDPAddr), cudp.WithScratchPool(pool))
	require.NoError(t, err)
	t.Cleanup(func() { _ = assoc.Close() })

	target := assoc.Conn.LocalAddr().(*net.UDPAddr)
	payload := []byte("buffer-reuse")
	spec := protocol.AddrSpec{AddrType: protocol.ATYPIPv4, IP: net.IPv4(127, 0, 0, 1), Port: 9999}
	dg := protocol.Datagram{DstAddr: spec, Data: payload}
	wire := dg.Bytes()
	buf := make([]byte, len(payload))

	if _, err := relay.WriteToUDP(wire, target); err != nil {
		t.Fatalf("write warmup: %v", err)
	}
	_, _, _, err = assoc.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, payload, buf[:len(payload)])

	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_, _ = relay.WriteToUDP(wire, target)
			}
		}
	}()
	defer close(stop)

	_ = testing.AllocsPerRun(50, func() {
		if _, _, _, err := assoc.ReadFrom(buf); err != nil {
			panic(err)
		}
	})
	require.LessOrEqual(t, atomic.LoadInt32(&newCalls), int32(2))
	require.Equal(t, payload, buf[:len(payload)])
}
