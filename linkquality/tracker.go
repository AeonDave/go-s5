package linkquality

import (
	"context"
	"errors"
	"math"
	"net"
	"sync"
	"time"
)

// EndpointKind describes what is being measured.
type EndpointKind string

const (
	EndpointUnknown EndpointKind = "unknown"
	EndpointSOCKS5  EndpointKind = "socks5"
	EndpointTCP     EndpointKind = "tcp"
)

// Metadata exposes the contextual information for a monitored link.
type Metadata struct {
	// Name is a human-readable label for the link (e.g. "exit-eu-1").
	Name string `json:"name"`
	// RemoteAddr describes the target address (host:port).
	RemoteAddr string `json:"remote_addr"`
	// Kind conveys whether this is a raw TCP hop or another SOCKS5 hop.
	Kind EndpointKind `json:"kind"`
	// TLS indicates whether TLS is negotiated on top of the transport.
	TLS bool `json:"tls"`
	// Notes lets callers propagate implementation-specific hints (e.g. cipher suite, provider name).
	Notes string `json:"notes"`
}

// RTTStats holds latency measurements.
type RTTStats struct {
	Min    time.Duration `json:"min"`
	Avg    time.Duration `json:"avg"`
	Max    time.Duration `json:"max"`
	StdDev time.Duration `json:"std_dev"`
}

// ThroughputStats tracks transfer speed estimates in bytes per second.
type ThroughputStats struct {
	Samples    int64   `json:"samples"`
	AverageBps float64 `json:"average_bps"`
	MinBps     float64 `json:"min_bps"`
	MaxBps     float64 `json:"max_bps"`
	TotalBytes int64   `json:"total_bytes"`
}

// ConnectionInfo surfaces the full state of the link.
type ConnectionInfo struct {
	Metadata    Metadata        `json:"metadata"`
	Probes      int             `json:"probes"`
	Success     int             `json:"success"`
	Failures    int             `json:"failures"`
	SuccessRate float64         `json:"success_rate"`
	RTT         RTTStats        `json:"rtt"`
	Jitter      time.Duration   `json:"jitter"`
	Throughput  ThroughputStats `json:"throughput"`
	Uptime      time.Duration   `json:"uptime"`
	UptimeRatio float64         `json:"uptime_ratio"`
	Downtime    time.Duration   `json:"downtime"`
	StartedAt   time.Time       `json:"started_at"`
	LastProbe   time.Time       `json:"last_probe"`
	LastError   string          `json:"last_error"`
	Composite   int             `json:"score"`
}

// Tracker aggregates link quality metrics in a thread-safe way.
type Tracker struct {
	mu sync.Mutex

	meta      Metadata
	started   time.Time
	lastProbe time.Time
	lastErr   string

	probes   int
	success  int
	failures int

	rttCount int64
	rttMin   time.Duration
	rttMax   time.Duration
	rttMean  float64
	rttM2    float64

	throughputCount int64
	throughputMean  float64
	throughputM2    float64
	throughputMin   float64
	throughputMax   float64
	totalBytes      int64

	stateUp          bool
	stateChangedAt   time.Time
	recordedDowntime time.Duration
}

// measuredConn wraps a net.Conn to passively account for throughput without
// changing connection behaviour. It records observed bytes and timings to the
// associated tracker and otherwise delegates everything to the underlying
// connection.
type measuredConn struct {
	net.Conn
	tracker *Tracker
}

func (c *measuredConn) CloseWrite() error {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

// NewTracker creates a monitor bound to the provided metadata.
func NewTracker(meta Metadata) *Tracker {
	now := time.Now()
	return &Tracker{
		meta:           meta,
		started:        now,
		lastProbe:      now,
		stateUp:        true,
		stateChangedAt: now,
	}
}

// WrapConn returns a connection that measures read/write throughput using the
// provided tracker. A nil tracker allocates a default tracker with unknown
// metadata. The wrapper is intentionally lightweight and avoids altering
// deadlines, TCP options, or keep-alive settings so it stays non-invasive.
func WrapConn(conn net.Conn, tracker *Tracker) net.Conn {
	if conn == nil {
		return nil
	}
	if tracker == nil {
		tracker = NewTracker(Metadata{Kind: EndpointUnknown})
	}
	return &measuredConn{Conn: conn, tracker: tracker}
}

// RecordProbe registers a single probe attempt with optional RTT. Passing a nil error marks success.
func (t *Tracker) RecordProbe(rtt time.Duration, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.probes++
	t.lastProbe = time.Now()
	if err != nil {
		t.failures++
		t.lastErr = err.Error()
	} else {
		t.success++
	}

	if err == nil && rtt > 0 {
		t.updateRTT(rtt)
	}
}

// RecordThroughput records an observed payload transfer.
func (t *Tracker) RecordThroughput(bytes int64, duration time.Duration) {
	if duration <= 0 || bytes <= 0 {
		return
	}
	rate := float64(bytes) / duration.Seconds()

	t.mu.Lock()
	defer t.mu.Unlock()

	t.totalBytes += bytes
	t.updateThroughput(rate)
}

func (c *measuredConn) Read(b []byte) (int, error) {
	start := time.Now()
	n, err := c.Conn.Read(b)
	c.tracker.RecordThroughput(int64(n), time.Since(start))
	return n, err
}

func (c *measuredConn) Write(b []byte) (int, error) {
	start := time.Now()
	n, err := c.Conn.Write(b)
	c.tracker.RecordThroughput(int64(n), time.Since(start))
	return n, err
}

// MarkDown marks the link as unavailable starting from now.
func (t *Tracker) MarkDown() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.updateState(false)
}

// MarkUp marks the link as available starting from now.
func (t *Tracker) MarkUp() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.updateState(true)
}

// Score returns the composite metric in the range [0,100].
func (t *Tracker) Score() int {
	info := t.ConnectionInfo()
	return info.Composite
}

// ConnectionInfo returns the full snapshot of current metrics.
func (t *Tracker) ConnectionInfo() ConnectionInfo {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	uptime, downtime, uptimeRatio := t.computeUptime(now)

	info := ConnectionInfo{
		Metadata:    t.meta,
		Probes:      t.probes,
		Success:     t.success,
		Failures:    t.failures,
		SuccessRate: successRatio(t.success, t.probes),
		Uptime:      uptime,
		UptimeRatio: uptimeRatio,
		Downtime:    downtime,
		StartedAt:   t.started,
		LastProbe:   t.lastProbe,
		LastError:   t.lastErr,
	}

	if t.rttCount > 0 {
		avg := time.Duration(t.rttMean)
		stdDev := time.Duration(math.Sqrt(t.rttM2 / float64(t.rttCount)))
		info.RTT = RTTStats{
			Min:    t.rttMin,
			Avg:    avg,
			Max:    t.rttMax,
			StdDev: stdDev,
		}
		info.Jitter = stdDev
	}

	if t.throughputCount > 0 {
		info.Throughput = ThroughputStats{
			Samples:    t.throughputCount,
			AverageBps: t.throughputMean,
			MinBps:     t.throughputMin,
			MaxBps:     t.throughputMax,
			TotalBytes: t.totalBytes,
		}
	}

	info.Composite = compositeScore(info)
	return info
}

func (t *Tracker) updateRTT(rtt time.Duration) {
	if t.rttCount == 0 {
		t.rttMin = rtt
		t.rttMax = rtt
	}
	if rtt < t.rttMin {
		t.rttMin = rtt
	}
	if rtt > t.rttMax {
		t.rttMax = rtt
	}

	t.rttCount++
	x := float64(rtt)
	delta := x - t.rttMean
	t.rttMean += delta / float64(t.rttCount)
	t.rttM2 += delta * (x - t.rttMean)
}

func (t *Tracker) updateThroughput(rate float64) {
	if t.throughputCount == 0 {
		t.throughputMin = rate
		t.throughputMax = rate
	}
	if rate < t.throughputMin {
		t.throughputMin = rate
	}
	if rate > t.throughputMax {
		t.throughputMax = rate
	}

	t.throughputCount++
	delta := rate - t.throughputMean
	t.throughputMean += delta / float64(t.throughputCount)
	t.throughputM2 += delta * (rate - t.throughputMean)
}

func (t *Tracker) updateState(up bool) {
	if t.stateUp == up {
		return
	}
	now := time.Now()
	if !t.stateUp {
		t.recordedDowntime += now.Sub(t.stateChangedAt)
	}
	t.stateUp = up
	t.stateChangedAt = now
}

func (t *Tracker) computeUptime(now time.Time) (uptime, downtime time.Duration, ratio float64) {
	elapsed := now.Sub(t.started)
	downtime = t.recordedDowntime
	if !t.stateUp {
		downtime += now.Sub(t.stateChangedAt)
	}
	if downtime < 0 {
		downtime = 0
	}
	if elapsed <= 0 {
		return 0, downtime, 1
	}
	uptime = elapsed - downtime
	if uptime < 0 {
		uptime = 0
	}
	ratio = float64(uptime) / float64(elapsed)
	return uptime, downtime, ratio
}

// ProbeTCP performs count dial attempts against addr using the given timeout and returns the collected ConnectionInfo.
// If tracker is nil a new one is created using TCP metadata.
func ProbeTCP(addr string, count int, timeout time.Duration, tracker *Tracker) (ConnectionInfo, error) {
	if count <= 0 {
		count = 5
	}
	if timeout <= 0 {
		timeout = 1 * time.Second
	}
	if tracker == nil {
		tracker = NewTracker(Metadata{RemoteAddr: addr, Kind: EndpointTCP})
	}

	for i := 0; i < count; i++ {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, timeout)
		elapsed := time.Since(start)
		if err != nil {
			tracker.RecordProbe(elapsed, err)
		} else {
			tracker.RecordProbe(elapsed, nil)
			_ = conn.Close()
		}
		time.Sleep(25 * time.Millisecond)
	}

	return tracker.ConnectionInfo(), nil
}

// ProbeSOCKSHandshake measures the handshake/connection health when dialing through a SOCKS5 hop.
// The dial function is expected to perform the SOCKS5 negotiation (including TLS if needed) and return
// an established connection that will be closed immediately after the probe.
func ProbeSOCKSHandshake(ctx context.Context, dial func(context.Context) (net.Conn, error), tracker *Tracker) (ConnectionInfo, error) {
	if dial == nil {
		return ConnectionInfo{}, errors.New("dial function is required")
	}
	if tracker == nil {
		tracker = NewTracker(Metadata{Kind: EndpointSOCKS5})
	}

	start := time.Now()
	conn, err := dial(ctx)
	elapsed := time.Since(start)
	if err != nil {
		tracker.RecordProbe(elapsed, err)
		return tracker.ConnectionInfo(), err
	}
	tracker.RecordProbe(elapsed, nil)
	_ = conn.Close()
	return tracker.ConnectionInfo(), nil
}

func compositeScore(info ConnectionInfo) int {
	successScore := info.SuccessRate

	var latencyScore float64
	latMs := float64(info.RTT.Avg.Milliseconds())
	switch {
	case latMs == 0:
		latencyScore = 0
	case latMs <= 50:
		latencyScore = 1
	case latMs <= 250:
		latencyScore = 1 - (latMs-50)/200*0.5
	case latMs <= 1000:
		latencyScore = 0.5 - (latMs-250)/750*0.5
	default:
		latencyScore = 0
	}
	if latencyScore < 0 {
		latencyScore = 0
	}

	jitterScore := 1.0
	jitterMs := float64(info.Jitter.Milliseconds())
	if jitterMs > 1 {
		switch {
		case jitterMs <= 10:
			jitterScore = 1
		case jitterMs <= 100:
			jitterScore = 1 - (jitterMs-10)/90
		default:
			jitterScore = 0
		}
	}
	if jitterScore < 0 {
		jitterScore = 0
	}

	throughputScore := 0.0
	if info.Throughput.Samples > 0 {
		rate := info.Throughput.AverageBps
		const floor = 128 * 1024        // 128 KB/s
		const ceiling = 5 * 1024 * 1024 // ~5 MB/s
		switch {
		case rate <= 0:
			throughputScore = 0
		case rate <= floor:
			throughputScore = (rate / floor) * 0.6
		case rate >= ceiling:
			throughputScore = 1
		default:
			throughputScore = 0.6 + (rate-floor)/(ceiling-floor)*0.4
		}
	}

	uptimeScore := info.UptimeRatio

	final := 100 * (0.35*successScore + 0.25*latencyScore + 0.15*jitterScore + 0.15*throughputScore + 0.1*uptimeScore)
	if final < 0 {
		final = 0
	}
	if final > 100 {
		final = 100
	}
	return int(math.Round(final))
}

func successRatio(success, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(success) / float64(total)
}
