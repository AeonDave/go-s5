package server

import (
	"net/netip"
	"testing"
	"time"
)

func TestIPRateLimiterBurstAndRefill(t *testing.T) {
	l := newIPRateLimiter(2, 3) // 2 conns/s sustained, bursts of 3
	addr := netip.MustParseAddr("203.0.113.7")
	now := time.Unix(1000, 0)

	for i := range 3 {
		if !l.allow(addr, now) {
			t.Fatalf("burst connection %d should be allowed", i+1)
		}
	}
	if l.allow(addr, now) {
		t.Fatal("4th connection in the same instant should be limited")
	}

	// After 500ms one token (2/s) has refilled.
	now = now.Add(500 * time.Millisecond)
	if !l.allow(addr, now) {
		t.Fatal("connection after refill should be allowed")
	}
	if l.allow(addr, now) {
		t.Fatal("second connection before next refill should be limited")
	}
}

func TestIPRateLimiterIsolatesSources(t *testing.T) {
	l := newIPRateLimiter(1, 1)
	now := time.Unix(1000, 0)

	if !l.allow(netip.MustParseAddr("198.51.100.1"), now) {
		t.Fatal("first source should be allowed")
	}
	if l.allow(netip.MustParseAddr("198.51.100.1"), now) {
		t.Fatal("first source should now be limited")
	}
	if !l.allow(netip.MustParseAddr("198.51.100.2"), now) {
		t.Fatal("an unrelated source must not be affected")
	}
}

func TestIPRateLimiterSweepBoundsMemory(t *testing.T) {
	l := newIPRateLimiter(100, 1) // idle cutoff = max(burst/rate, 1s) = 1s
	now := time.Unix(1000, 0)

	// Fill the table past the sweep threshold with distinct sources.
	for i := range sweepThreshold + 16 {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		l.allow(a, now)
	}
	if len(l.buckets) <= sweepThreshold {
		t.Fatalf("setup: expected table above threshold, got %d", len(l.buckets))
	}

	// Far enough in the future that every bucket is idle-refilled; the next
	// insert beyond the threshold must trigger a sweep that drops them all.
	now = now.Add(time.Hour)
	l.allow(netip.MustParseAddr("192.0.2.1"), now)
	if got := len(l.buckets); got > 2 {
		t.Fatalf("sweep should have dropped idle buckets, table still has %d", got)
	}
}
