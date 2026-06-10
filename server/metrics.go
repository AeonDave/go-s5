package server

import (
	"sync/atomic"
)

// RejectReason explains why the accept loop refused a connection before the
// SOCKS handshake started.
type RejectReason string

// Rejection reasons reported to Metrics.ConnRejected.
const (
	// RejectMaxConnections means the WithMaxConnections cap was reached.
	RejectMaxConnections RejectReason = "max_connections"
	// RejectRateLimited means the per-source rate limit configured with
	// WithConnectionRateLimit was exceeded.
	RejectRateLimited RejectReason = "rate_limited"
)

// Metrics receives server lifecycle events for observability backends
// (Prometheus, OpenTelemetry, expvar, ...). All methods are invoked inline on
// the serving path, so implementations must be safe for concurrent use and
// return quickly; anything slow should be offloaded by the implementation.
//
// Install with WithMetrics. When no Metrics is configured the server skips
// every call site with a single nil check — there is no other overhead.
type Metrics interface {
	// ConnAccepted is called when the accept loop admits a connection.
	ConnAccepted()
	// ConnClosed is called when an admitted connection finishes.
	ConnClosed()
	// ConnRejected is called when the accept loop refuses a connection
	// before the handshake (connection cap or rate limit).
	ConnRejected(reason RejectReason)
	// Request is called once per parsed SOCKS request with the command byte
	// (protocol.CommandConnect, CommandBind or CommandAssociate).
	Request(command byte)
	// RequestDone is called when the request finishes; err is nil on success.
	RequestDone(command byte, err error)
	// RelayBytes reports payload bytes moved by the proxy: once per finished
	// CONNECT/BIND tunnel (both directions summed) and once per relayed UDP
	// batch. The sum over time is total relayed traffic.
	RelayBytes(n int64)
}

// CounterMetrics is a ready-to-use Metrics implementation backed by atomic
// counters. It is suitable for tests, expvar publishing, or as a starting
// point for custom backends.
type CounterMetrics struct {
	accepted     atomic.Int64
	closed       atomic.Int64
	rejected     atomic.Int64
	requests     atomic.Int64
	requestFails atomic.Int64
	relayedBytes atomic.Int64
}

// MetricsSnapshot is a point-in-time copy of CounterMetrics values.
type MetricsSnapshot struct {
	Accepted     int64 // connections admitted by the accept loop
	Closed       int64 // admitted connections that have finished
	Rejected     int64 // connections refused before the handshake
	Requests     int64 // SOCKS requests started
	RequestFails int64 // SOCKS requests that returned an error
	RelayedBytes int64 // total payload bytes relayed (TCP tunnels + UDP)
}

// ConnAccepted implements Metrics.
func (m *CounterMetrics) ConnAccepted() { m.accepted.Add(1) }

// ConnClosed implements Metrics.
func (m *CounterMetrics) ConnClosed() { m.closed.Add(1) }

// ConnRejected implements Metrics.
func (m *CounterMetrics) ConnRejected(RejectReason) { m.rejected.Add(1) }

// Request implements Metrics.
func (m *CounterMetrics) Request(byte) { m.requests.Add(1) }

// RequestDone implements Metrics.
func (m *CounterMetrics) RequestDone(_ byte, err error) {
	if err != nil {
		m.requestFails.Add(1)
	}
}

// RelayBytes implements Metrics.
func (m *CounterMetrics) RelayBytes(n int64) { m.relayedBytes.Add(n) }

// Snapshot returns a consistent-enough copy of all counters for reporting.
func (m *CounterMetrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		Accepted:     m.accepted.Load(),
		Closed:       m.closed.Load(),
		Rejected:     m.rejected.Load(),
		Requests:     m.requests.Load(),
		RequestFails: m.requestFails.Load(),
		RelayedBytes: m.relayedBytes.Load(),
	}
}
