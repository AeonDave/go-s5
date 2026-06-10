package server

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// ipRateLimiter implements a per-source-IP token bucket evaluated once per
// accepted connection, before the SOCKS handshake. Buckets are created on
// demand and the table is swept lazily, so memory stays bounded even under a
// spoofed-source flood: a sweep removes every bucket that has been idle long
// enough to refill completely (it carries no information beyond "full").
type ipRateLimiter struct {
	rate  float64 // tokens added per second
	burst float64 // bucket capacity

	mu        sync.Mutex
	buckets   map[netip.Addr]*tokenBucket
	lastSweep time.Time
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// sweepThreshold is the table size above which allow() considers sweeping
// idle buckets; sweepMinInterval bounds how often the O(n) sweep can run.
const (
	sweepThreshold   = 4096
	sweepMinInterval = time.Second
)

func newIPRateLimiter(perSecond float64, burst int) *ipRateLimiter {
	if burst < 1 {
		burst = 1
	}
	return &ipRateLimiter{
		rate:    perSecond,
		burst:   float64(burst),
		buckets: make(map[netip.Addr]*tokenBucket),
	}
}

// allow reports whether a connection from addr may proceed, consuming one
// token if so. It runs in O(1) amortized time.
func (l *ipRateLimiter) allow(addr netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[addr]
	if !ok {
		if len(l.buckets) >= sweepThreshold {
			l.sweepLocked(now)
		}
		l.buckets[addr] = &tokenBucket{tokens: l.burst - 1, last: now}
		return true
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// sweepLocked drops buckets idle long enough to be full again. Callers hold mu.
func (l *ipRateLimiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < sweepMinInterval {
		return
	}
	l.lastSweep = now
	// After idle = burst/rate seconds a bucket is indistinguishable from a
	// fresh one, so it can be dropped without changing behavior.
	idleCutoff := max(time.Duration(l.burst/l.rate*float64(time.Second)), time.Second)
	deadline := now.Add(-idleCutoff)
	for addr, b := range l.buckets {
		if b.last.Before(deadline) {
			delete(l.buckets, addr)
		}
	}
}

// allowConn extracts the source IP from conn and applies the limiter.
// Connections with non-TCP or unparsable remote addresses are admitted.
func (l *ipRateLimiter) allowConn(conn net.Conn) bool {
	addr := remoteIP(conn)
	if !addr.IsValid() {
		return true
	}
	return l.allow(addr, time.Now())
}

func remoteIP(conn net.Conn) netip.Addr {
	switch ra := conn.RemoteAddr().(type) {
	case *net.TCPAddr:
		return ra.AddrPort().Addr().Unmap()
	case *net.UDPAddr:
		return ra.AddrPort().Addr().Unmap()
	default:
		if ra == nil {
			return netip.Addr{}
		}
		if ap, err := netip.ParseAddrPort(ra.String()); err == nil {
			return ap.Addr().Unmap()
		}
		return netip.Addr{}
	}
}
