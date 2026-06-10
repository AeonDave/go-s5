package auth

import "io"

// Authenticator negotiates one SOCKS5 authentication method. Authenticate
// reads the method sub-negotiation from the client reader, writes the reply
// to the writer, and returns the resulting AContext; the string argument is
// the client's network address for store lookups. GetCode returns the SOCKS5
// method code the authenticator implements.
type Authenticator interface {
	Authenticate(io.Reader, io.Writer, string) (*AContext, error)
	GetCode() uint8
}

// CredentialStore validates a username/password pair. userAddr is the
// client's network address, allowing per-source policies.
type CredentialStore interface {
	Valid(user, password, userAddr string) bool
}
