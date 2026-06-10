# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest release (v1.x) | ✅ |
| older releases | ❌ — please upgrade |

go-s5 follows semantic versioning. Security fixes are released as patch
versions of the latest minor release.

## Reporting a Vulnerability

Please **do not open a public issue** for security problems.

Report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/AeonDave/go-s5/security/advisories/new)
("Report a vulnerability" on the repository's Security tab).

Include where possible:

- the affected component (server, client, protocol parsers, UDP relay, ...)
- a minimal reproduction or proof of concept
- the impact you believe it has (e.g. crash, memory exhaustion, auth bypass,
  traffic misdirection)

You can expect an acknowledgment within 7 days. Once a fix is available the
advisory is published together with the patched release; reporters are
credited unless they prefer otherwise.

## Scope notes

- The wire-format parsers are continuously fuzzed in CI
  (`internal/protocol`); crashes found there are treated as security issues.
- Denial-of-service resistance is a design goal: handshake timeouts,
  connection caps, per-source rate limiting and UDP peer limits are
  first-class options. Reports that bypass these bounds (unbounded memory or
  goroutine growth from untrusted input) are in scope.
- Deployments terminating TLS themselves (`ListenAndServeTLS`) should follow
  standard `crypto/tls` hardening guidance; TLS misconfiguration in user code
  is out of scope.
