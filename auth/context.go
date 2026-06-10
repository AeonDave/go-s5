// Package auth implements SOCKS5 method negotiation and authentication:
// the NoAuth and Username/Password (RFC 1929) authenticators, the
// CredentialStore abstraction backing them, and the AContext carrying
// authentication results to rules, middleware and handlers.
package auth

// AContext is the result of a successful authentication. Method is the
// negotiated SOCKS5 method code and Payload carries method-specific data —
// for example the authenticated "username", or the tls.* keys populated by
// the server when serving over mutual TLS.
type AContext struct {
	Method  uint8
	Payload map[string]string
}
