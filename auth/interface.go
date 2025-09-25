package auth

import "io"

type Authenticator interface {
	Authenticate(io.Reader, io.Writer, string) (*AuthContext, error)
	GetCode() uint8
}

type CredentialStore interface {
	Valid(user, password, userAddr string) bool
}
