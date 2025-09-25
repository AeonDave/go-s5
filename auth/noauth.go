package auth

import (
	"go-s5/internal/protocol"
	"io"
)

type NoAuthAuthenticator struct{}

func (a NoAuthAuthenticator) GetCode() uint8 { return protocol.MethodNoAuth }

func (a NoAuthAuthenticator) Authenticate(_ io.Reader, writer io.Writer, _ string) (*AuthContext, error) {
	_, err := writer.Write([]byte{protocol.VersionSocks5, protocol.MethodNoAuth})
	return &AuthContext{Method: protocol.MethodNoAuth, Payload: map[string]string{}}, err
}
