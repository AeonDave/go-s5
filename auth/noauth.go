package auth

import (
	"io"

	"github.com/AeonDave/go-s5/internal/protocol"
)

// NoAuthAuthenticator implements the "no authentication required" method
// (0x00). It is the default when the server has no credential store.
type NoAuthAuthenticator struct{}

// GetCode implements Authenticator.
func (a NoAuthAuthenticator) GetCode() uint8 { return protocol.MethodNoAuth }

// Authenticate implements Authenticator: it acknowledges the method and
// returns an empty AContext.
func (a NoAuthAuthenticator) Authenticate(_ io.Reader, writer io.Writer, _ string) (*AContext, error) {
	_, err := writer.Write([]byte{protocol.VersionSocks5, protocol.MethodNoAuth})
	return &AContext{Method: protocol.MethodNoAuth, Payload: map[string]string{}}, err
}
