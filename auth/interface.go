package auth

import "io"

type Authenticator interface {
	Authenticate(io.Reader, io.Writer, string) (*AContext, error)
	GetCode() uint8
}

type CredentialStore interface {
	Valid(user, password, userAddr string) bool
}
