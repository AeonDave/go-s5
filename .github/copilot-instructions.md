# go-s5 Copilot Instructions

## Architecture & Responsibilities
- `server/` accepts TCP clients, negotiates methods, populates `handler.Request` (context, metadata, auth), then dispatches to CONNECT/BIND/ASSOCIATE handlers (`server.connect.go`, `bind.go`, `associate.go`).
- `handler/` defines the request façade plus middleware chains; wire-level structs live in `protocol/` (public) and `internal/protocol` (server-only fast paths).
- `auth/`, `rules/`, `resolver/`, and `handler.AddressRewriter` are pluggable interfaces wired through `server.Option`s so upstream code can inject policy without touching transport logic.
- `client/` mirrors the protocol: `client.Client` handles negotiation, multi-hop dialing, and exposes helpers in `client/tcp` and `client/udp` to wrap established tunnels.
- `cmd/s5` is the reference CLI: `s5 server` exercises server options (TLS/mTLS, upstream chaining) and `s5 dial` is a quick client that reuses the same packages plus link-quality metrics.

## Extension & Configuration Patterns
- Prefer `server.With...` options to customize behavior (auth, rules, resolver, bind IPs, timeouts, custom dialers, metadata hooks); see `server/option.go` for available knobs and mimic existing option helpers when adding new ones.
- Use middleware hooks (`server.WithConnectMiddleware` etc.) for cross-cutting concerns—each middleware receives the `handler.Request` plus writer so it can log, mutate context, or short-circuit replies.
- TLS-aware deployments rely on `AuthContext.Payload` enrichment in `server.enrichAuthFromTLS`; rules/auth modules expect keys like `tls.subject` or `tls.fingerprint.sha256` to already exist—preserve these when extending auth flows.
- Upstream chaining is implemented with `server.WithDialAndRequest` (see `cmd/s5/main.go`); ensure UDP requests fall back to direct `net.Dialer` because upstream SOCKS implementations are TCP-only.
- `handler.AddressRewriter` should treat passed `*protocol.AddrSpec` as immutable—copy and adjust like `examples` in README to avoid data races when buffers are reused.

## Networking & Performance Expectations
- Respect context deadlines everywhere: server sets handshake deadlines (`Server.applyHandshakeDeadline`) and cancels per-connection goroutines when contexts fire; new code must propagate ctx to dials, middleware, and goroutine pools (`Server.gPool`).
- Duplex proxying uses pooled buffers (`internal/buffer/pool.go`) plus `io.WriterTo`/`io.ReaderFrom` fast paths—reuse `Server.borrowBuf`/`Server.proxyDuplex` rather than rolling custom copy loops.
- UDP associate enforces peer caps (`udpMaxPeers`), idle GC, and drops fragmented datagrams by design (`protocol.Datagram.Frag` check); keep those invariants when touching UDP paths.
- BIND flows expect two replies and optional peer validation (`WithBindPeerCheckIPOnly`); coordinate with tests in `test/bind_*.go` whenever altering reply order or validation.

## Client Helpers & Observability
- `client.DialChain` builds multi-hop tunnels by recursively CONNECTing and Handshake-ing; when augmenting, keep the single-stream constraint and reuse `protocol.ParseAddrSpec` for hop parsing.
- Expose high-level helpers through `client/tcp.Stream` and `client/udp.Association` instead of raw `net.Conn` so callers benefit from built-in deadline helpers and relay utilities.
- `linkquality/tracker.go` passively instruments existing dials and streams; CLI uses `linkquality.WrapConn` and `Tracker.RecordProbe`—always record durations/errors from real operations instead of generating synthetic traffic.

## Build, Test, Debug Workflow
- Go 1.24+ is required; module root exports `server`, `client`, and `protocol` packages consumed directly (`go get github.com/AeonDave/go-s5/server ...`).
- Fast manual checks: `go build ./cmd/s5` then run `./s5 server -listen :1080 [...]` and `./s5 dial -socks 127.0.0.1:1080 -dest example.com:80 -stdio`.
- The integration-heavy suite lives under `test/`; run `go test ./...` (takes ~1-2 minutes). Targeted runs (`go test ./test -run BindPeerCheck`) are encouraged when iterating on protocol flows.
- Many tests spin up live listeners and UDP sockets—avoid hard-coding ports/IPs in new tests; prefer helpers already in `test/*.go` to allocate ephemeral endpoints.
- Logging conventions: use `server.Logger` / `client/internal/logging` abstractions so library consumers can swap verbosity; avoid direct `log.Printf` outside CLI utilities.
