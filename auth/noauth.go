package auth

import (
	"io"

	"github.com/AeonDave/go-s5/internal/protocol"
)

type NoAuthAuthenticator struct{}

func (a NoAuthAuthenticator) GetCode() uint8 { return protocol.MethodNoAuth }

func (a NoAuthAuthenticator) Authenticate(_ io.Reader, writer io.Writer, _ string) (*AContext, error) {
	_, err := writer.Write([]byte{protocol.VersionSocks5, protocol.MethodNoAuth})
	return &AContext{Method: protocol.MethodNoAuth, Payload: map[string]string{}}, err
}
