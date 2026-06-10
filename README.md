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
- Flexible dialing: `WithDial`, `WithDialAndRequest`, `WithDialer`
- First-class client with multi-hop chaining (`DialChain`) over a single stream
- Graceful shutdown: `Shutdown(ctx)` drains connections; `Close()` tears down immediately
- UDP ASSOCIATE: peer limits, idle GC, FQDN handling
- Link quality monitoring via `linkquality.Tracker` with passive throughput and RTT tracking

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
| | `WithLogger(Logger)` | Replace the server logger |
| | `WithBufferPool(buffer.BufPool)` | Replace the proxy I/O buffer pool |
| | `WithConnectionLogging(bool)` | Log accept/close events with peer addresses |
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
