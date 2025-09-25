package auth

import (
	"go-s5/internal/protocol"
	"io"
)

type UserPassAuthenticator struct {
	Credentials CredentialStore
}

func (a UserPassAuthenticator) GetCode() uint8 { return protocol.MethodUserPassAuth }

func (a UserPassAuthenticator) Authenticate(reader io.Reader, writer io.Writer, userAddr string) (*AuthContext, error) {
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
	return &AuthContext{
		Method: protocol.MethodUserPassAuth,
		Payload: map[string]string{
			"username": string(nup.User),
		},
	}, nil
}
