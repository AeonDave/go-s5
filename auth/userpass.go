package auth

import (
	"io"

	"github.com/AeonDave/go-s5/internal/protocol"
)

// UserPassAuthenticator implements Username/Password authentication
// (RFC 1929, method 0x02) backed by a CredentialStore.
type UserPassAuthenticator struct {
	Credentials CredentialStore
}

// GetCode implements Authenticator.
func (a UserPassAuthenticator) GetCode() uint8 { return protocol.MethodUserPassAuth }

// Authenticate implements Authenticator: it runs the RFC 1929
// sub-negotiation and validates the pair against the credential store. On
// success the AContext payload carries the authenticated "username".
func (a UserPassAuthenticator) Authenticate(reader io.Reader, writer io.Writer, userAddr string) (*AContext, error) {
	if _, err := writer.Write([]byte{protocol.VersionSocks5, protocol.MethodUserPassAuth}); err != nil {
		return nil, err
	}

	nup, err := protocol.ParseUserPassRequest(reader)
	if err != nil {
		return nil, err
	}

	if !a.Credentials.Valid(string(nup.User), string(nup.Pass), userAddr) {
		_, _ = writer.Write([]byte{protocol.UserPassAuthVersion, protocol.AuthFailure})
		return nil, protocol.ErrUserAuthFailed
	}

	_, _ = writer.Write([]byte{protocol.UserPassAuthVersion, protocol.AuthSuccess})
	return &AContext{
		Method: protocol.MethodUserPassAuth,
		Payload: map[string]string{
			"username": string(nup.User),
		},
	}, nil
}
