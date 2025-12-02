# go-s5 AGENTS.md

## Dev environment tips
- Go 1.24+ is required; module root exports `server`, `client`, and `protocol` packages.
- Fast manual checks: `go build ./cmd/s5` then run `./s5 server -listen :1080 [...]` and `./s5 dial -socks 127.0.0.1:1080 -dest example.com:80 -stdio`.
- Use `go mod tidy` to clean up dependencies after adding or removing imports.
- Check the `go.mod` file to confirm module name and dependencies.

## Project Structure
- `server/` – TCP server, method negotiation, CONNECT/BIND/ASSOCIATE handlers.
- `handler/` – Request façade and middleware chains.
- `protocol/` – Public wire-level structs.
- `internal/protocol` – Server-only fast paths.
- `auth/`, `rules/`, `resolver/` – Pluggable interfaces wired through `server.Option`s.
- `client/` – Protocol mirroring: negotiation, multi-hop dialing, helpers in `client/tcp` and `client/udp`.
- `cmd/s5` – Reference CLI: `s5 server` and `s5 dial`.
- `linkquality/` – Passive instrumentation for dials and streams.
- `test/` – Integration-heavy test suite.

## Testing instructions
- Find the CI plan in the `.github/workflows` folder (CodeQL Advanced workflow).
- Run `go test ./...` to run the full test suite (takes ~1-2 minutes).
- Targeted runs: `go test ./test -run <TestName>` for specific protocol flows.
- Many tests spin up live listeners and UDP sockets—avoid hard-coding ports/IPs; use helpers in `test/*.go` for ephemeral endpoints.
- Fix any test or type errors until the whole suite is green.
- After moving files or changing imports, run `go vet ./...` and `go fmt ./...` to ensure code quality.
- Add or update tests for the code you change, even if nobody asked.

## PR instructions
- Title format: `[<package>] <Title>` (e.g., `[server] Add new middleware hook`)
- Always run `go test ./...`, `go vet ./...`, and `go fmt ./...` before committing.
- Ensure all tests pass and there are no linting errors.
- Follow existing code conventions and patterns.

## Extension & Configuration Patterns
- Prefer `server.With...` options to customize behavior (auth, rules, resolver, bind IPs, timeouts, custom dialers, metadata hooks); see [`server/option.go`](server/option.go) for available knobs.
- Use middleware hooks (`server.WithConnectMiddleware` etc.) for cross-cutting concerns.
- TLS-aware deployments rely on `AuthContext.Payload` enrichment; rules/auth modules expect keys like `tls.subject` or `tls.fingerprint.sha256`.
- Upstream chaining is implemented with `server.WithDialAndRequest`; ensure UDP requests fall back to direct `net.Dialer`.
- `handler.AddressRewriter` should treat passed `*protocol.AddrSpec` as immutable—copy and adjust to avoid data races.

## Networking & Performance Expectations
- Respect context deadlines everywhere: server sets handshake deadlines and cancels per-connection goroutines when contexts fire.
- Duplex proxying uses pooled buffers (`internal/buffer/pool.go`) plus `io.WriterTo`/`io.ReaderFrom` fast paths—reuse `Server.borrowBuf`/`Server.proxyDuplex`.
- UDP associate enforces peer caps, idle GC, and drops fragmented datagrams by design.
- BIND flows expect two replies and optional peer validation; coordinate with tests in `test/bind_*.go`.

## Logging conventions
- Use `server.Logger` / `client/internal/logging` abstractions so library consumers can swap verbosity.
- Avoid direct `log.Printf` outside CLI utilities.
