# go-s5

A minimal, fast, and extensible SOCKS5 library written in Go.

[![CI](https://github.com/AeonDave/go-s5/actions/workflows/go.yml/badge.svg)](https://github.com/AeonDave/go-s5/actions/workflows/go.yml)
[![CodeQL](https://github.com/AeonDave/go-s5/actions/workflows/codeql.yml/badge.svg)](https://github.com/AeonDave/go-s5/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/AeonDave/go-s5)](https://goreportcard.com/report/github.com/AeonDave/go-s5)
![GitHub License](https://img.shields.io/github/license/AeonDave/go-s5)

## Features

- Full RFC 1928: CONNECT, BIND, and UDP ASSOCIATE
- Pluggable authentication: NoAuth and Username/Password; mTLS via TLS listener
- Rules/ACL: `rules.RuleSet` interface (default `PermitAll`)
- Custom DNS resolver (`resolver.NameResolver`) and address rewriter (`handler.AddressRewriter`)
- Per-command middleware and optional full command-handler replacement
- Flexible dialing: `WithDial`, `WithDialAndRequest`, `WithDialer`, `WithDialFQDN` (Happy Eyeballs)
- First-class client with multi-hop chaining (`DialChain`) over a single stream
- Graceful shutdown: `Shutdown(ctx)` drains connections; `Close()` tears down immediately
- UDP ASSOCIATE: batched syscalls on Linux (`recvmmsg`/`sendmmsg`), per-flow DNS caching, peer limits, idle GC
- Admission control: `WithMaxConnections` cap and `WithConnectionRateLimit` per-source token bucket
- Observability: `WithMetrics` hook (connections, requests, relayed bytes), `log/slog` adapter, link quality monitoring via `linkquality.Tracker`
- Fuzz-tested wire parsers with committed regression corpus; race-clean test suite

## Performance

Measured on loopback with the benchmarks in `test/bench_test.go`
(`go test -bench . -benchmem -run xxx ./test/`), Go 1.25, 16 hardware threads.

| Metric | Linux | Windows |
|---|---|---|
| TCP relay throughput, single stream | ~3.8 GB/s | ~1.5 GB/s |
| TCP relay throughput, 16 concurrent streams | ~11.4 GB/s | ~9.4 GB/s |
| Relay-path allocations | 0 /op | 0 /op |
| UDP proxied round trip (256 B payload) | ~28 µs | ~40 µs |
| UDP sustained relay (200 B datagram flood) | ~200–260k pps | ~75–110k pps |

How it gets there:

- **TCP**: the relay preserves Go's `io.Copy` fast paths in both directions, so
  on Linux data moves kernel-side via `splice(2)` and never enters user space.
  The relay adds single-digit % overhead over the theoretical loopback floor.
- **UDP**: on Linux up to 8 datagrams move per syscall (`recvmmsg`/`sendmmsg`);
  the posted buffer set starts at 2 and doubles only under sustained bursts, so
  sparse flows stay at the memory footprint of unbatched code. The per-flow
  SOCKS header is pre-written into each buffer and payloads land directly
  after it — zero per-packet copies on the return path.
- **Hot paths allocate nothing**: flow keys are `netip.AddrPort` structs (no
  per-packet strings), peer-limit checks are O(1) against an atomic counter,
  source validation is precomputed per association, FQDN destinations resolve
  once per flow within a 30 s TTL (stale entries serve as fallback during DNS
  blips), and buffers come from a shared `sync.Pool`.
- **Per connection**: handshake readers are pooled, command handler chains are
  prebuilt at `New()`, and an idle UDP association pins ~64 KiB.

### Behavior under congestion

The server is designed to degrade predictably — shedding load instead of
growing memory:

- **TCP backpressure is end-to-end.** The relay never queues internally: a slow
  receiver propagates flow control back to the sender through the tunnel, and
  per-tunnel memory stays constant regardless of how far ahead the fast side
  gets.
- **UDP sheds at the kernel boundary.** There is no userspace packet queue; if
  a flood exceeds relay capacity, excess datagrams drop in the socket buffer
  and memory does not grow. In the flood benchmark above the relay sustains
  84–97% delivery on Linux at peak ingest rates.
- **Hostile traffic is bounded.** `WithMaxConnections` rejects connections
  beyond the cap with an O(1) check before any SOCKS traffic, and
  `WithConnectionRateLimit` throttles per-source handshake floods with token
  buckets whose table is swept under spoofed-source pressure, so its memory
  stays bounded too. `WithHandshakeTimeout` kills stalled handshakes,
  `WithUDPAssociateLimits` caps peers per association with an O(1) check and
  reaps idle flows, fragmented datagrams are dropped, and datagram sources
  are validated against the expected client address.
- **The accept loop survives resource exhaustion.** Temporary accept errors
  (e.g. out of file descriptors) trigger exponential backoff from 5 ms up to
  1 s instead of busy-looping or exiting.
- **DNS instability does not kill flows.** Per-flow resolutions are cached
  with a 30 s TTL and stale entries keep serving while the resolver is failing.

## Comparison

How go-s5 compares with the Go SOCKS5 libraries it is most often weighed
against (based on upstream repositories as of June 2026):

| | **go-s5** | [things-go/go-socks5] | [armon/go-socks5] | [txthinking/socks5] | [x/net/proxy] |
|---|---|---|---|---|---|
| Server | ✅ | ✅ | ✅ | ✅ | — |
| Client | ✅ | — | — | ✅ | ✅ |
| CONNECT | ✅ | ✅ | ✅ | ✅ | ✅ |
| BIND | ✅ | — | — | — | — |
| UDP ASSOCIATE | ✅ | ✅ | — | ✅ | — |
| Username/Password auth | ✅ | ✅ | ✅ | ✅ | ✅ |
| mTLS client identity → rules | ✅ | — | — | — | — |
| Multi-hop chaining (one stream) | ✅ | — | — | — | ✅¹ |
| Batched UDP syscalls (`recvmmsg`/`sendmmsg`) | ✅ | — | — | — | — |
| Zero-alloc relay hot paths | ✅ | — | — | — | n/a |
| `splice(2)` TCP fast path (Linux) | ✅ | ✅² | ✅² | — | n/a |
| Connection cap / per-IP rate limiting | ✅ | — | — | ✅³ | — |
| Metrics hook | ✅ | — | — | — | — |
| Graceful shutdown (`Shutdown(ctx)`) | ✅ | — | — | — | n/a |
| Per-command middleware | ✅ | ✅ | — | — | — |
| Link quality scoring | ✅ | — | — | — | — |
| Fuzz-tested protocol parsers | ✅ | — | — | — | — |
| Committed reproducible benchmarks | ✅ | — | — | — | — |
| Actively maintained | ✅ | ✅ | — (archived-style, last commits ~2016) | ✅ | ✅ |

¹ via repeated `proxy.SOCKS5` dialer wrapping (one TCP hop per dialer, client only).
² inherited implicitly when `io.Copy` sees raw `*net.TCPConn`s; not preserved through wrappers.
³ txthinking/socks5 exposes a global TCP timeout/limit, not per-source token buckets.

[things-go/go-socks5]: https://github.com/things-go/go-socks5
[armon/go-socks5]: https://github.com/armon/go-socks5
[txthinking/socks5]: https://github.com/txthinking/socks5
[x/net/proxy]: https://pkg.go.dev/golang.org/x/net/proxy

## Install

Requires Go 1.25+.

```
go get github.com/AeonDave/go-s5/server \
       github.com/AeonDave/go-s5/client \
       github.com/AeonDave/go-s5/protocol
```

## Quick start

```go
package main

import (
    "log"
    "time"

    socks5 "github.com/AeonDave/go-s5/server"
)

func main() {
    s := socks5.New(
        socks5.WithHandshakeTimeout(5*time.Second),
        socks5.WithTCPKeepAlive(30*time.Second),
    )
    log.Fatal(s.ListenAndServe("tcp", ":1080"))
}
```

## Graceful shutdown

`ServeContext` binds a context to the accept loop; canceling it tears down every
active connection immediately. For a gentler stop, use `Shutdown`:

```go
srv := socks5.New()
ln, _ := net.Listen("tcp", ":1080")

// Start serving in the background.
go srv.ServeContext(context.Background(), ln)

// ... later, stop accepting and wait for in-flight connections to finish.
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
if err := srv.Shutdown(ctx); err != nil {
    // ctx expired before all conns drained — force them down.
    _ = srv.Close()
}
```

- `Shutdown(ctx)` closes all listeners so no new connections are accepted, then
  polls until active connections reach zero or `ctx` expires.
- `Close()` closes all listeners and cancels every active connection immediately.
- `Serve`, `ServeContext`, `ListenAndServe`, and `ListenAndServeTLS` return
  `server.ErrServerClosed` after either call.

## Server options

| Category | Option | Notes |
|---|---|---|
| **Auth** | `WithAuthMethods([]auth.Authenticator)` | Append custom authenticators |
| | `WithCredential(auth.CredentialStore)` | Enable User/Pass with a credential store |
| **Rules / Resolver / Rewriter** | `WithRule(rules.RuleSet)` | ACL evaluated before dialing |
| | `WithResolver(resolver.NameResolver)` | Custom DNS resolver |
| | `WithRewriter(handler.AddressRewriter)` | Mutate destination before dialing |
| **Dialing** | `WithDial(func(ctx, network, addr) (net.Conn, error))` | Custom dial function |
| | `WithDialAndRequest(func(ctx, network, addr, *handler.Request) (net.Conn, error))` | Dial with full request context |
| | `WithDialer(net.Dialer)` | Custom `net.Dialer` for outbound connections |
| | `WithDialFQDN(bool)` | CONNECT dials hostnames directly (Happy Eyeballs, RFC 8305) instead of pre-resolving |
| **Admission control** | `WithMaxConnections(int)` | Cap concurrent connections; excess closed before handshake (O(1)) |
| | `WithConnectionRateLimit(perSecond float64, burst int)` | Per-source-IP token bucket; excess closed before handshake |
| **TCP / BIND / UDP** | `WithHandshakeTimeout(time.Duration)` | Deadline for negotiation + request parsing |
| | `WithTCPKeepAlive(time.Duration)` | TCP keepalive period on accepted connections |
| | `WithBindIP(net.IP)` | Bind IP for BIND and UDP sockets |
| | `WithBindAcceptTimeout(time.Duration)` | Max wait for peer during BIND |
| | `WithBindPeerCheckIPOnly(bool)` | Validate BIND peer by IP only (ignore port) |
| | `WithUseBindIpBaseResolveAsUdpAddr(bool)` | Advertise bind IP in UDP ASSOCIATE reply |
| | `WithUDPAssociateLimits(maxPeers int, idleTimeout time.Duration)` | Peer cap and idle GC |
| **Lifecycle hooks** | `WithBaseContext(func(net.Listener) context.Context)` | Base context factory per listener |
| | `WithConnContext(func(context.Context, net.Conn) context.Context)` | Decorate per-connection context |
| | `WithConnState(func(net.Conn, server.ConnState))` | Observe StateNew / StateActive / StateClosed |
| | `WithConnMetadata(func(net.Conn) map[string]string)` | Attach static metadata to `handler.Request.Metadata` |
| **Infra** | `WithGPool(GPool)` | Goroutine pool for request handling |
| | `WithLogger(Logger)` | Replace the server logger (`NewSlogLogger` adapts `log/slog`) |
| | `WithBufferPool(buffer.BufPool)` | Replace the proxy I/O buffer pool |
| | `WithConnectionLogging(bool)` | Log accept/close events with peer addresses |
| | `WithMetrics(server.Metrics)` | Receive connection/request/relay-bytes events |
| | `WithLinkQuality(*linkquality.Tracker)` | Attach a tracker for outbound hop quality |

## Authentication

**NoAuth** is the default when no credentials are configured.

**Username/Password** — pass a `auth.StaticCredentials` map (implements
`auth.CredentialStore`), or supply a custom `CredentialStore` to
`WithCredential`:

```go
creds := auth.StaticCredentials{"alice": "secret", "bob": "p@ss"}
s := socks5.New(socks5.WithCredential(creds))
log.Fatal(s.ListenAndServe("tcp", ":1080"))
```

**Mutual TLS** — start the server on a TLS listener and set
`ClientAuth: tls.RequireAndVerifyClientCert`. When TLS is active, the server
automatically populates `auth.AContext.Payload` with the following keys from
the client leaf certificate:

- `tls.subject`, `tls.issuer`
- `tls.san.dns`, `tls.san.ip`
- `tls.fingerprint.sha256`

These keys are available to rules, middleware, and custom handlers.

```go
tlsCfg := &tls.Config{
    Certificates: []tls.Certificate{cert},
    ClientAuth:   tls.RequireAndVerifyClientCert,
    ClientCAs:    caPool,
}
s := socks5.New(socks5.WithHandshakeTimeout(5 * time.Second))
log.Fatal(s.ListenAndServeTLS("tcp", ":1080", tlsCfg))
```

## Client

**Single-hop CONNECT:**

```go
conn, _ := net.Dial("tcp", "127.0.0.1:1080")
cli := client.New(
    client.WithHandshakeTimeout(5*time.Second),
    client.WithIOTimeout(10*time.Second),
)
_, _ = cli.Handshake(ctx, conn, nil) // NoAuth; pass *client.Credentials for user/pass
dst, _ := protocol.ParseAddrSpec("example.com:80")
_, _ = cli.Connect(ctx, conn, dst)
// conn is now tunneled to example.com:80
```

Use `cli.ConnectStream` to get a `*tcp.Stream` with helpers like `WriteString`,
`ReadFull`, `CopyTo/CopyFrom`, and `Relay` (bidirectional proxy with context
cancellation). Use `cli.UDPAssociate` to get a `*client.UDPAssociation` with
`WriteTo`/`ReadFrom`/`PacketConn()`. Use `cli.Bind` (or `BindStart`/`BindWait`)
for BIND.

**Multi-hop DialChain:**

```go
chain := []client.Hop{
    {Address: "10.0.0.2:1080", Creds: &client.Credentials{Username: "alice", Password: "secret"}},
    {Address: "hop2.example:1080", TLSConfig: &tls.Config{ServerName: "hop2.example", MinVersion: tls.VersionTLS12}},
}
cli := client.New(client.WithHandshakeTimeout(5*time.Second), client.WithIOTimeout(10*time.Second))
conn, err := cli.DialChain(ctx, chain, "example.org:443", 5*time.Second)
if err != nil { /* handle */ }
defer conn.Close()
// conn speaks to example.org:443 through 2 SOCKS hops over a single stream.
```

Per-hop `Creds` and `TLSConfig` are optional. Pass an empty `finalTarget` to
stop at the last hop and issue `UDPAssociate` or `Bind` directly.
The `client/tcp` and `client/udp` packages provide focused APIs for stream and
datagram workloads; the root `client` package re-exports them for backwards compatibility.

## CLI

Build:

```
go build -o s5 ./cmd/s5
```

**Server examples:**

```
# NoAuth, plain TCP
s5 server -listen :1080

# User/Pass with tuning
s5 server -listen :1080 -user alice -pass secret -handshake-timeout 5s -tcp-keepalive 30s

# TLS + optional mTLS
s5 server -listen :1080 -tls-cert cert.pem -tls-key key.pem -mtls-ca ca.pem

# Chain through an upstream SOCKS5 hop
s5 server -listen :1080 -upstream 1.2.3.4:1080 -upstream-user alice -upstream-pass secret

# Log connections and track outbound link quality
s5 server -listen :1080 -log-connections -linkquality -linkquality-interval 3s
```

**Dial examples:**

```
# Send an HTTP request and print response
s5 dial -socks 127.0.0.1:1080 -dest example.com:80 -send $'GET / HTTP/1.0\r\n\r\n' -io-timeout 5s

# Stdio tunnel (e.g. for SSH ProxyCommand)
s5 dial -socks 127.0.0.1:1080 -dest example.com:22 -stdio

# Show live link quality during a session
s5 dial -socks 127.0.0.1:1080 -dest example.com:443 -linkquality -stdio
```

## Link quality monitoring

The `linkquality` package provides a thread-safe `Tracker` that passively
observes existing traffic — it never sends additional probes or alters socket
options.

```go
tracker := linkquality.NewTracker(linkquality.Metadata{
    Name: "exit-eu-1",
    Kind: linkquality.EndpointSOCKS5,
    TLS:  true,
})

// Record an existing handshake latency — no extra packets sent.
start := time.Now()
_, err := cli.Handshake(ctx, conn, creds)
tracker.RecordProbe(time.Since(start), err)

// Passively track throughput on the established stream.
measured := linkquality.WrapConn(conn, tracker)

score := tracker.Score()           // composite 0–100
info := tracker.ConnectionInfo()   // RTT, jitter, throughput, uptime, etc.
```

Key entry points:
- `NewTracker(Metadata)` — creates a tracker
- `RecordProbe(rtt, err)` — register a probe result (RTT + success/failure)
- `WrapConn(net.Conn, *Tracker) net.Conn` — passively record throughput
- `Score() int` — composite score 0–100
- `ConnectionInfo() ConnectionInfo` — full snapshot (RTT min/avg/max, jitter, throughput, uptime)
- `ProbeTCP` / `ProbeSOCKSHandshake` — optional active health-check helpers

On the server side, pass `server.WithLinkQuality(tracker)` and read
`srv.LinkQualityTracker()` to monitor outbound hop health. The CLI flags
`-linkquality` / `-linkquality-interval` emit periodic snapshots to stderr for
both `s5 server` and `s5 dial`.

## Observability

`WithMetrics` installs a hook that receives connection, request and relay
events. `server.CounterMetrics` is a ready-made atomic implementation; any
backend (Prometheus, OpenTelemetry, expvar) can implement the same interface.
When no hook is installed the only cost on the serving path is a nil check —
byte counts are taken from the relay's own return values, so the `splice(2)`
and batched-UDP fast paths are untouched.

```go
metrics := &server.CounterMetrics{}
s := socks5.New(
    socks5.WithMetrics(metrics),
    socks5.WithMaxConnections(4096),
    socks5.WithConnectionRateLimit(10, 20), // per source IP: 20 burst, 10/s sustained
    socks5.WithLogger(socks5.NewSlogLogger(slog.Default())),
)
// ... later
snap := metrics.Snapshot()
log.Printf("active=%d relayed=%dB rejected=%d",
    snap.Accepted-snap.Closed, snap.RelayedBytes, snap.Rejected)
```

Rejections (connection cap, rate limit) happen before any SOCKS byte is
exchanged and are reported with their reason.

## Middleware

`handler.Middleware` is `func(ctx context.Context, w io.Writer, req *handler.Request) error`.
Returning a non-nil error aborts the request before the command handler runs.

```go
logMW := handler.Middleware(func(ctx context.Context, w io.Writer, r *handler.Request) error {
    log.Printf("cmd=%d src=%s dst=%s", r.Command, r.RemoteAddr, r.DestAddr)
    return nil
})

s := socks5.New(
    socks5.WithConnectMiddleware(logMW),
    socks5.WithBindMiddleware(logMW),
    socks5.WithAssociateMiddleware(logMW),
)
```

Full handler replacement is available via `WithConnectHandle`, `WithBindHandle`,
and `WithAssociateHandle`.

## Compatibility

- Conforms to SOCKS5 (RFC 1928) for CONNECT, BIND, and UDP ASSOCIATE.
- REP codes are mapped accurately from typical dial errors.
- UDP: fragmented datagrams (`FRAG != 0`) are dropped and not reassembled.
- BIND: the incoming peer is validated against the expected address; set
  `WithBindPeerCheckIPOnly(true)` to match by IP only (ignore port).

## Testing

```
go test ./...
```

The test suite is race-clean (`-race`) and runs on every push via CI.

Every wire-format parser (`ParseRequest`, `ParseReply`, `ParseMethodRequest`,
`ParseUserPassRequest`, `ParseDatagram`, `ParseAddrSpec`) has a native Go
fuzz target asserting no-panic and encode/decode round-trip stability:

```
go test -fuzz=FuzzParseDatagram -fuzztime=30s ./internal/protocol/
```

The seed corpus is replayed on every plain `go test` run, so past fuzz
findings act as permanent regression tests.
