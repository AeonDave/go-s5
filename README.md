# go-s5

A minimal, fast, and extensible SOCKS5 server lib written in Go. 
It implements the three primary commands from RFC 1928: CONNECT, BIND, and UDP ASSOCIATE. The library exposes clear extension points for authentication, authorization, DNS resolution, address rewriting, and per‑command middleware. It also includes pragmatic I/O optimizations for high throughput.

Contents
- Overview
- Features
- Install
- Quick Start
- CLI (s5)
- Authentication (NoAuth, User/Pass, mTLS)
- Options (With... API)
- Client API (CONNECT/BIND/UDP, Multi-hop)
- Examples
  - Basic server
  - Username/password
  - TLS and mTLS
  - Custom rules
  - Custom resolver
  - Address rewriter
  - Middleware
  - Upstream chaining
  - Client: multi-hop DialChain
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
- First-class client with multi-hop chaining over a single stream (Handshake+CONNECT per hop)
- TCP options: handshake timeout, TCP keep‑alive
- BIND tuning: bind IP, accept timeout, peer validation mode
- UDP ASSOCIATE: udp4/udp6 selection, FQDN handling, peer limits with idle GC, optional bind IP
- I/O performance: buffer pool, fast‑paths, half‑close, duplex proxy
- Logging and goroutine pool (GPool) integration

Install
- Go 1.24+
- As a library (server, client, protocol):
```
go get github.com/AeonDave/go-s5/server github.com/AeonDave/go-s5/client github.com/AeonDave/go-s5/protocol
```
Import examples:
```
import socks5 "github.com/AeonDave/go-s5/server"
import client "github.com/AeonDave/go-s5/client"
import socks5protocol "github.com/AeonDave/go-s5/protocol"
```

CLI (s5)
- Build the CLI:
```
go build -o s5 ./cmd/s5
```
- Start a server on :1080 (NoAuth by default):
```
./s5 server -listen :1080
```
- With username/password and handshake/keepalive tuning:
```
./s5 server -listen :1080 -user alice -pass secret -handshake-timeout 5s -tcp-keepalive 30s
```
- With TLS and optional mTLS:
```
./s5 server -listen :1080 -tls-cert cert.pem -tls-key key.pem -mtls-ca ca.pem
```
- Test a CONNECT via the client helper (prints response to stdout):
```
./s5 dial -socks 127.0.0.1:1080 -dest example.com:80 -send $'GET / HTTP/1.0\r\n\r\n' -io-timeout 5s
```
- Open a stdio tunnel to a destination:
```
./s5 dial -socks 127.0.0.1:1080 -dest example.com:80 -stdio
```

Quick Start
Minimal server on :1080 (no authentication):
```
package main

import (
    "log"
    socks5 "github.com/AeonDave/go-s5/server"
)

func main() {
    s := socks5.New()
    log.Fatal(s.ListenAndServe("tcp", ":1080"))
}
```

Client API (CONNECT/BIND/UDP, Multi-hop)
- Create a client, perform Handshake, then CONNECT/BIND/UDP as needed.
- For multi-hop, use DialChain to build N hops over the same stream (Handshake+CONNECT per hop), then CONNECT to the final target.

Single hop CONNECT example:
```
conn, _ := net.Dial("tcp", "127.0.0.1:1080")
cli := client.New(client.WithHandshakeTimeout(5*time.Second), client.WithIOTimeout(5*time.Second))
_, _ = cli.Handshake(ctx, conn, nil) // NoAuth
dst, _ := socks5protocol.ParseAddrSpec("example.com:80")
_, _ = cli.Connect(ctx, conn, dst)
```

Multi-hop DialChain (client-side chaining):
```
chain := []client.Hop{
  { Address: "10.0.0.2:1080", Creds: &client.Credentials{Username:"alice", Password:"secret"} },
  { Address: "hop3.example:1080", /* TLSConfig: myTLS */ },
}
cli := client.New(client.WithHandshakeTimeout(5*time.Second), client.WithIOTimeout(5*time.Second))
conn, err := cli.DialChain(ctx, chain, "example.org:443", 5*time.Second)
if err != nil { /* handle */ }
defer conn.Close()
// conn now speaks to example.org:443 through 2 SOCKS hops over a single stream
```

Notes:
- Per-hop creds/TLS are optional via Hop.{Creds,TLSConfig}.
- DialChain respects ctx and client timeouts; set WithHandshakeTimeout/WithIOTimeout.
- You can also call the method form: `cli.DialChain(ctx, chain, final, 5*time.Second)`.

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
s := socks5.New(
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

s := socks5.New(
    socks5.WithHandshakeTimeout(5*time.Second),
)
log.Fatal(s.ListenAndServeTLS("tcp", ":1080", cfg))
```
Note: when TLS is enabled, the server completes the handshake early and enriches `AuthContext.Payload` with client certificate identity (subject, issuer, SANs, SHA‑256 fingerprint) for rules/ACLs or logging.

Username/password authentication
```
creds := auth.StaticCredentials{"alice": "secret", "bob": "p@ss"}
s := socks5.New(
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

s := socks5.New(
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

s := socks5.New(
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

s := socks5.New(socks5.WithRewriter(rewriteToLocal{}))
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

s := socks5.New(
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

s := socks5.New(socks5.WithDial(dial))
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

Client: multi-hop DialChain
```
chain := []client.Hop{{Address:"127.0.0.1:1080"}, {Address:"10.0.0.2:1080"}}
cli := client.New(client.WithHandshakeTimeout(5*time.Second), client.WithIOTimeout(5*time.Second))
conn, err := cli.DialChain(ctx, chain, "ifconfig.me:443", 5*time.Second)
```

Advanced BIND options
```
s := socks5.New(
    socks5.WithBindIP(net.ParseIP("0.0.0.0")),
    socks5.WithBindAcceptTimeout(30*time.Second),
    socks5.WithBindPeerCheckIPOnly(true), // validate peer by IP only
)
```

Advanced UDP ASSOCIATE options
```
s := socks5.New(
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
s := socks5.New(
    socks5.WithHandshakeTimeout(5*time.Second),
    socks5.WithTCPKeepAlive(30*time.Second),
)
```

Buffer pool tuning and GPool integration
```
// 64 KiB buffer pool
s := socks5.New(
    socks5.WithBufferPool(buffer.NewPool(64*1024)),
)

// Integrate with an external goroutine pool
var myPool GPool = newMyPool()
s = socks5.New(socks5.WithGPool(myPool))
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

Client multi-hop DialChain and UDP/BIND examples

Multi-hop DialChain
```
chain := []client.Hop{
  { Address: "127.0.0.1:1080" },
  { Address: "10.0.0.2:1080" },
}
cli := client.New(client.WithHandshakeTimeout(5*time.Second), client.WithIOTimeout(5*time.Second))
conn, err := cli.DialChain(ctx, chain, "ifconfig.me:443", 5*time.Second)
if err != nil { /* handle */ }
defer conn.Close()
```

Per-hop TLS and credentials
```
chain := []client.Hop{
  { Address: "10.0.0.2:1080", Creds: &client.Credentials{Username: "alice", Password: "secret"} },
  { Address: "hop3.example:1080", TLSConfig: &tls.Config{ServerName: "hop3.example", MinVersion: tls.VersionTLS12} },
}
cli := client.New(client.WithHandshakeTimeout(5*time.Second), client.WithIOTimeout(5*time.Second))
conn, err := cli.DialChain(ctx, chain, "example.org:443", 5*time.Second)
```

Notes:
- Per-hop creds/TLS are optional via Hop.{Creds,TLSConfig}.
- DialChain respects ctx and client timeouts; set client.WithHandshakeTimeout/client.WithIOTimeout.
- Control the first-hop dial with client.WithDialer (custom net.Dialer) or the dialTimeout argument.

UDP and BIND on the last hop
```
// Build the TCP chain first
// Pass empty finalTarget to stop at the last hop and speak to the SOCKS server
cli := client.New(client.WithHandshakeTimeout(5*time.Second), client.WithIOTimeout(5*time.Second))
conn, err := cli.DialChain(ctx, chain, "", 5*time.Second)
if err != nil { /* handle */ }
defer conn.Close()

// UDP ASSOCIATE
assoc, rep, err := cli.UDPAssociate(ctx, conn)
if err != nil { /* handle */ }
defer assoc.Close()
dst := socks5protocol.AddrSpec{IP: net.ParseIP("127.0.0.1"), Port: 9999, AddrType: socks5protocol.ATYPIPv4}
_, _ = assoc.WriteTo(dst, []byte("ping"))

// BIND (two-step)
peer := socks5protocol.AddrSpec{IP: net.ParseIP("0.0.0.0"), Port: 0, AddrType: socks5protocol.ATYPIPv4}
first, second, err := cli.Bind(ctx, conn, peer)
_ = first; _ = second // see bind.go for details
```
