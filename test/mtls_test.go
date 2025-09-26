package socks5_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	socks5_handler "github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/internal/protocol"
	server "github.com/AeonDave/go-s5/server"

	"github.com/stretchr/testify/require"
)

func genCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return ca, key
}

func genCert(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, cn string, isClient bool, ips []net.IP, dns []string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
		IPAddresses:           ips,
		DNSNames:              dns,
	}
	if isClient {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	return tlsCert, cert
}

// Ensure mTLS handshake is required and TLS identity is exposed in AuthContext payload.
func TestTLS_MutualAuth_SucceedsAndExposesCert(t *testing.T) {
	ca, caKey := genCA(t)
	srvCert, _ := genCert(t, ca, caKey, "server", false, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	cliCert, _ := genCert(t, ca, caKey, "client", true, nil, []string{"client.local"})

	pool := x509.NewCertPool()
	pool.AddCert(ca)

	// Start TLS listener with client cert required
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	require.NoError(t, err)

	// Custom connect handler echoes tls.subject payload
	srv := server.New(
		server.WithLogger(server.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		server.WithConnectHandle(func(ctx context.Context, w io.Writer, r *socks5_handler.Request) error {
			// reply success first
			_ = server.SendReply(w, protocol.RepSuccess, &net.TCPAddr{IP: net.IPv4zero, Port: 0})
			subj := ""
			if r.AuthContext != nil {
				subj = r.AuthContext.Payload["tls.subject"]
			}
			_, _ = w.Write([]byte(subj))
			return nil
		}),
	)

	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(ln) }()
	defer func() { _ = ln.Close(); <-done }()

	// Client with cert connects
	clientTLS := &tls.Config{Certificates: []tls.Certificate{cliCert}, RootCAs: pool}
	c, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	require.NoError(t, err)
	defer func(c *tls.Conn) {
		_ = c.Close()
	}(c)

	// SOCKS method negotiation: NoAuth
	_, _ = c.Write([]byte{protocol.VersionSocks5, 1, protocol.MethodNoAuth})
	m := make([]byte, 2)
	_, err = io.ReadFull(c, m)
	require.NoError(t, err)

	// CONNECT with dummy addr
	req := bytes.NewBuffer(nil)
	head := protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandConnect, DstAddr: protocol.AddrSpec{IP: net.IPv4zero, Port: 0, AddrType: protocol.ATYPIPv4}}
	req.Write(head.Bytes())
	_, _ = c.Write(req.Bytes())

	rep, err := protocol.ParseReply(c)
	require.NoError(t, err)
	require.Equal(t, byte(protocol.RepSuccess), rep.Response)

	// Read echoed subject
	buf := make([]byte, 256)
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := c.Read(buf)
	_ = c.SetReadDeadline(time.Time{})
	require.NoError(t, err)
	require.Contains(t, string(buf[:n]), "CN=client")
}

// When client cert is missing, handshake must fail.
func TestTLS_MutualAuth_FailsWithoutClientCert(t *testing.T) {
	ca, caKey := genCA(t)
	srvCert, _ := genCert(t, ca, caKey, "server", false, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	require.NoError(t, err)
	defer func(ln net.Listener) {
		_ = ln.Close()
	}(ln)

	srv := server.New(server.WithLogger(server.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))))
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(ln) }()
	defer func() { _ = ln.Close(); <-done }()

	// No client cert: perform explicit TLS handshake to surface the error deterministically
	clientTLS := &tls.Config{RootCAs: pool}
	raw, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func(raw net.Conn) {
		_ = raw.Close()
	}(raw)
	tc := tls.Client(raw, clientTLS)
	err = tc.Handshake()
	require.Error(t, err)
}
