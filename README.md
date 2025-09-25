# go-s5

A minimal, fast, and extensible SOCKS5 server written in Go. It implements the three primary commands from RFC 1928: CONNECT, BIND, and UDP ASSOCIATE. The library exposes clear extension points for authentication, authorization, DNS resolution, address rewriting, and per‑command middleware. It also includes pragmatic I/O optimizations for high throughput.

Contents
- Overview
- Features
- Install
- Quick Start
- Authentication (NoAuth, User/Pass, mTLS)
- Options (With... API)
- Examples
  - Basic server
  - Username/password
  - TLS and mTLS
  - Custom rules
  - Custom resolver
  - Address rewriter
  - Middleware
  - Upstream chaining
  - Advanced BIND
  - Advanced UDP ASSOCIATE
- Performance Notes
- Compatibility
- Testing

Overview
This repository provides a reusable library to build SOCKS5 servers. It performs method negotiation, request parsing, and replies (REP with BND.ADDR/BND.PORT), then proxies data between the client and the target.

Features
- Full SOCKS5: CONNECT, BIND, UDP ASSOCIATE
- Pluggable authentication: NoAuth and Username/Password; transport‑level mTLS supported via TLS listener
- Rules/ACLs: customizable authorization (default PermitAll)
- DNS: custom resolver support
- Address rewriting: transform destination before dialing
- Per‑command middleware and optional custom handlers
- Flexible dialing: WithDial, WithDialAndRequest, WithDialer
- TCP options: handshake timeout, TCP keep‑alive
- BIND tuning: bind IP, accept timeout, peer validation mode
- UDP ASSOCIATE: udp4/udp6 selection, FQDN handling, peer limits with idle GC, optional bind IP
- I/O performance: buffer pool, fast‑paths, half‑close, duplex proxy
- Logging and goroutine pool (GPool) integration

Install
- Go 1.24+
- As a library:
```
go get go-s5
```
Import:
```
import socks5 "go-s5"
```

Quick Start
Minimal server on :1080 (no authentication):
```
package main

import (
    "log"
    socks5 "go-s5"
)

func main() {
    s := socks5.NewServer()
    log.Fatal(s.ListenAndServe("tcp", ":1080"))
}
```

Authentication
- NoAuth (default)
  - Enabled when no credentials are provided.
- Username/Password
  - Provide `WithCredential(auth.StaticCredentials)` or `WithAuthMethods` including `auth.UserPassAuthenticator`.
- Mutual TLS (mTLS)
  - Run the server on a TLS listener with `ClientAuth: tls.RequireAndVerifyClientCert`.
  - Using `ListenAndServeTLS` automatically enriches the `AuthContext.Payload` with TLS peer details you can use in rules or logging:
    - `tls.subject`, `tls.issuer`, `tls.san.dns`, `tls.san.ip`, `tls.fingerprint.sha256`.
  - Example below in TLS and mTLS.

Options (With... API)
- Authentication
  - `WithAuthMethods([]auth.Authenticator)`
  - `WithCredential(auth.CredentialStore)`
- Rules/ACL
  - `WithRule(rules.RuleSet)`
- Resolver
  - `WithResolver(resolver.NameResolver)`
- Rewriter
  - `WithRewriter(handler.AddressRewriter)`
- Dialing
  - `WithDial(func(ctx, network, addr) (net.Conn, error))`
  - `WithDialAndRequest(func(ctx, network, addr, req) (net.Conn, error))`
  - `WithDialer(net.Dialer)`
- TCP
  - `WithHandshakeTimeout(time.Duration)`
  - `WithTCPKeepAlive(time.Duration)`
  - `WithBindIP(net.IP)`
- BIND
  - `WithBindAcceptTimeout(time.Duration)`
  - `WithBindPeerCheckIPOnly(bool)`
- UDP ASSOCIATE
  - `WithUseBindIpBaseResolveAsUdpAddr(bool)`
  - `WithUDPAssociateLimits(maxPeers int, idleTimeout time.Duration)`
- Infra
  - `WithGPool(GPool)`, `WithLogger(Logger)`, `WithBufferPool(buffer.BufPool)`

Examples
Basic server
```
s := socks5.NewServer(
    socks5.WithHandshakeTimeout(5*time.Second),
    socks5.WithTCPKeepAlive(30*time.Second),
)
log.Fatal(s.ListenAndServe("tcp", ":1080"))
```

TLS and mTLS
```
cfg := &tls.Config{
    Certificates: []tls.Certificate{cert},
    // For mTLS
    ClientAuth: tls.RequireAndVerifyClientCert,
    ClientCAs:  clientCAPool,
}

s := socks5.NewServer(
    socks5.WithHandshakeTimeout(5*time.Second),
)
log.Fatal(s.ListenAndServeTLS("tcp", ":1080", cfg))
```
Note: when TLS is enabled, the server completes the handshake early and enriches `AuthContext.Payload` with client certificate identity (subject, issuer, SANs, SHA‑256 fingerprint) for rules/ACLs or logging.

Username/password authentication
```
creds := auth.StaticCredentials{"alice": "secret", "bob": "p@ss"}
s := socks5.NewServer(
    socks5.WithCredential(creds), // automatically enables User/Pass
)
log.Fatal(s.ListenAndServe("tcp", ":1080"))
```

Custom rules/ACLs
The `rules` package provides a default `PermitAll`. You can implement your own `RuleSet`:
```
type onlyLocal struct{}
func (onlyLocal) Allow(ctx context.Context, req *handler.Request) (context.Context, bool) {
    ip := req.DestAddr.IP
    if ip.IsLoopback() || ip.IsPrivate() {
        return ctx, true
    }
    return ctx, false
}

s := socks5.NewServer(
    socks5.WithRule(onlyLocal{}),
)
```

Custom DNS resolver
```
type staticResolver struct{}
func (staticResolver) Resolve(ctx context.Context, host string) (context.Context, net.IP, error) {
    // example: force 1.2.3.4
    return ctx, net.ParseIP("1.2.3.4"), nil
}

s := socks5.NewServer(
    socks5.WithResolver(staticResolver{}),
)
```

Address rewriter
```
type rewriteToLocal struct{}
func (rewriteToLocal) Rewrite(ctx context.Context, r *handler.Request) (context.Context, *protocol.AddrSpec) {
    // redirect everything to the same port on 127.0.0.1
    d := *r.DestAddr
    d.IP = net.ParseIP("127.0.0.1")
    d.FQDN = ""
    return ctx, &d
}

s := socks5.NewServer(socks5.WithRewriter(rewriteToLocal{}))
```

Middleware for logging/metrics
```
logMW := handler.MiddlewareFunc(func(next handler.Handler) handler.Handler {
    return func(ctx context.Context, w io.Writer, r *handler.Request) error {
        start := time.Now()
        err := next(ctx, w, r)
        dur := time.Since(start)
        log.Printf("%s %s -> %s in %v (err=%v)", r.CommandName(), r.RemoteAddr, r.DestAddr, dur, err)
        return err
    }
})

s := socks5.NewServer(
    socks5.WithConnectMiddleware(logMW),
    socks5.WithBindMiddleware(logMW),
    socks5.WithAssociateMiddleware(logMW),
)
```

Upstream chaining (server-side)
Use `WithDial` or `WithDialAndRequest` to relay TCP traffic through another SOCKS5 proxy.
```
import xproxy "golang.org/x/net/proxy"

upstream, _ := xproxy.SOCKS5("tcp", "hop2.example:1080", nil, &net.Dialer{})

dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
    type ctxDialer interface{ DialContext(context.Context, string, string) (net.Conn, error) }
    if d, ok := upstream.(ctxDialer); ok { return d.DialContext(ctx, network, addr) }
    return upstream.Dial(network, addr)
}

s := socks5.NewServer(socks5.WithDial(dial))
```

Client-side chaining with ProxyChains
Example of a strict chain with 3 hops:
```
# ~/.proxychains/proxychains.conf
strict_chain
quiet_mode
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080
socks5 10.0.0.2 1080 user pass
socks5 example.last 1080
```
Run: `proxychains4 -q curl https://ifconfig.me`

Advanced BIND options
```
s := socks5.NewServer(
    socks5.WithBindIP(net.ParseIP("0.0.0.0")),
    socks5.WithBindAcceptTimeout(30*time.Second),
    socks5.WithBindPeerCheckIPOnly(true), // validate peer by IP only
)
```

Advanced UDP ASSOCIATE options
```
s := socks5.NewServer(
    socks5.WithUseBindIpBaseResolveAsUdpAddr(true), // bind UDP socket to bindIP
    socks5.WithUDPAssociateLimits(1024, 2*time.Minute), // peer limit and idle GC
)
```
Notes:
- For FQDN destinations, the server preserves the hostname and selects `udp4` or `udp6` to match the client’s address family.
- Datagram packets with `FRAG != 0` are dropped.

Performance Notes
- Proxy I/O uses a shared buffer pool and fast paths (`io.WriterTo`/`io.ReaderFrom`) where safe.
- To avoid platform‑specific hangs with certain reader implementations, the proxy prefers `WriteTo`, and selectively uses `ReadFrom` for well‑behaved readers (e.g., `*bytes.Reader`, `*strings.Reader`).
- The proxy attempts half‑closes (`CloseWrite`/`CloseRead`) where supported.

Handshake timeout and TCP keep-alive
```
s := socks5.NewServer(
    socks5.WithHandshakeTimeout(5*time.Second),
    socks5.WithTCPKeepAlive(30*time.Second),
)
```

Buffer pool tuning and GPool integration
```
// 64 KiB buffer pool
s := socks5.NewServer(
    socks5.WithBufferPool(buffer.NewPool(64*1024)),
)

// Integrate with an external goroutine pool
var myPool GPool = newMyPool()
s = socks5.NewServer(socks5.WithGPool(myPool))
```

Compatibility
- Conforms to SOCKS5 (RFC 1928) for CONNECT, BIND, and UDP ASSOCIATE.
- Accurate REP code mapping for typical dial errors.
- UDP: fragmented datagrams (FRAG != 0) are not supported.
- ProxyChains does not implement end‑to‑end UDP ASSOCIATE (only optional DNS‑over‑TCP).
- BIND: expected peer validation; with `WithBindPeerCheckIPOnly(true)`, matches by IP only.

Testing
Run the test suite:
```
go test ./...
```
