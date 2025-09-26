package socks5_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	socks5 "github.com/AeonDave/go-s5"
)

type spyDialer struct {
	t        *testing.T
	wantAddr string
	called   bool
	deadline time.Duration
}

func (s *spyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	s.called = true
	if s.wantAddr != "" && s.wantAddr != address {
		s.t.Errorf("spyDialer: got addr %s, want %s", address, s.wantAddr)
	}
	if dl, ok := ctx.Deadline(); ok {
		s.deadline = time.Until(dl)
	} else {
		s.deadline = 0
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestClientWithDialer_UsesDialer_And_AppliesTimeout_WhenNoCtxDeadline(t *testing.T) {
	sd := &spyDialer{t: t, wantAddr: "127.0.0.1:1080"}
	chain := []socks5.Hop{{Address: sd.wantAddr}}
	ctx := context.Background()
	start := time.Now()
	_, err := socks5.DialChain(ctx, chain, "example.org:443", 50*time.Millisecond, socks5.ClientWithDialer(sd))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("expected error due to timeout, got nil")
	}
	if !sd.called {
		t.Fatalf("custom dialer was not used")
	}
	if sd.deadline <= 0 {
		t.Fatalf("expected deadline to be set on ctx for dialer")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("expected dial to respect timeout, elapsed=%v", elapsed)
	}
}

func TestClientWithDialer_RespectsCallerCtxDeadline_OverDialTimeout(t *testing.T) {
	sd := &spyDialer{t: t, wantAddr: "127.0.0.1:1081"}
	chain := []socks5.Hop{{Address: sd.wantAddr}}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := socks5.DialChain(ctx, chain, "example.org:443", 2*time.Second, socks5.ClientWithDialer(sd))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("expected error due to caller ctx deadline, got nil")
	}
	if !sd.called {
		t.Fatalf("custom dialer was not used")
	}
	// The provided ctx already had a deadline; library should not override with dialTimeout.
	if sd.deadline <= 0 || sd.deadline > time.Second {
		t.Fatalf("unexpected or missing deadline on ctx for dialer: %v", sd.deadline)
	}
	if elapsed > time.Second {
		t.Fatalf("expected to finish within caller deadline, elapsed=%v", elapsed)
	}
	_ = errors.Is(err, context.DeadlineExceeded)
}
