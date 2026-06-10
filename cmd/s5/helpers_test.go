package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AeonDave/go-s5/linkquality"

	"github.com/stretchr/testify/require"
)

// writeSelfSignedPEM writes a self-signed cert/key pair (PEM) into dir and
// returns the file paths.
func writeSelfSignedPEM(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "s5-cli-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
	require.NoError(t, certOut.Close())

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyOut, err := os.Create(keyPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	require.NoError(t, keyOut.Close())
	return certPath, keyPath
}

func TestParseServerFlags(t *testing.T) {
	cfg := parseServerFlags([]string{
		"-listen", ":2080",
		"-user", "alice",
		"-pass", "secret",
		"-bind-ip", "127.0.0.1",
		"-handshake-timeout", "5s",
		"-tcp-keepalive", "30s",
		"-tls-cert", "c.pem",
		"-tls-key", "k.pem",
		"-mtls-ca", "ca.pem",
		"-upstream", "10.0.0.1:1080",
		"-upstream-user", "bob",
		"-upstream-pass", "pw",
		"-log-connections",
		"-linkquality",
		"-linkquality-interval", "2s",
	})
	require.Equal(t, ":2080", cfg.listen)
	require.Equal(t, "alice", cfg.user)
	require.Equal(t, "secret", cfg.pass)
	require.Equal(t, "127.0.0.1", cfg.bindIP)
	require.Equal(t, "5s", cfg.hs)
	require.Equal(t, "30s", cfg.ka)
	require.Equal(t, "c.pem", cfg.tlsCert)
	require.Equal(t, "k.pem", cfg.tlsKey)
	require.Equal(t, "ca.pem", cfg.mtlsCA)
	require.Equal(t, "10.0.0.1:1080", cfg.upstream)
	require.Equal(t, "bob", cfg.upstreamUser)
	require.Equal(t, "pw", cfg.upstreamPass)
	require.True(t, cfg.logConns)
	require.True(t, cfg.linkquality)
	require.Equal(t, 2*time.Second, cfg.lqInterval)

	// Defaults
	def := parseServerFlags(nil)
	require.Equal(t, ":1080", def.listen)
	require.False(t, def.logConns)
	require.Equal(t, 5*time.Second, def.lqInterval)
}

func TestServerOptionsFromConfig_Variants(t *testing.T) {
	// bind IP invalid
	_, _, err := serverOptionsFromConfig(serverFlags{bindIP: "not-an-ip"})
	require.Error(t, err)

	// bind IP valid + timeouts + credentials + linkquality
	opts, tracker, err := serverOptionsFromConfig(serverFlags{
		bindIP: "127.0.0.1", hs: "5s", ka: "10s",
		user: "alice", pass: "secret",
		linkquality: true,
	})
	require.NoError(t, err)
	require.NotNil(t, tracker)
	require.NotEmpty(t, opts)

	// linkquality with upstream uses SOCKS5 metadata
	_, tracker2, err := serverOptionsFromConfig(serverFlags{upstream: "203.0.113.1:1080", linkquality: true})
	require.NoError(t, err)
	require.NotNil(t, tracker2)
	require.Equal(t, linkquality.EndpointSOCKS5, tracker2.ConnectionInfo().Metadata.Kind)
}

func TestTLSConfigFromFlags(t *testing.T) {
	// no TLS flags: nil config, nil error
	cfg, err := tlsConfigFromFlags(serverFlags{})
	require.NoError(t, err)
	require.Nil(t, cfg)

	// cert without key: error
	_, err = tlsConfigFromFlags(serverFlags{tlsCert: "only-cert.pem"})
	require.Error(t, err)

	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedPEM(t, dir)

	// valid pair
	cfg, err = tlsConfigFromFlags(serverFlags{tlsCert: certPath, tlsKey: keyPath})
	require.NoError(t, err)
	require.Len(t, cfg.Certificates, 1)
	require.Equal(t, tls.ClientAuthType(0), cfg.ClientAuth)

	// valid pair + mTLS CA
	cfg, err = tlsConfigFromFlags(serverFlags{tlsCert: certPath, tlsKey: keyPath, mtlsCA: certPath})
	require.NoError(t, err)
	require.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
	require.NotNil(t, cfg.ClientCAs)

	// mTLS CA unreadable
	_, err = tlsConfigFromFlags(serverFlags{tlsCert: certPath, tlsKey: keyPath, mtlsCA: filepath.Join(dir, "missing.pem")})
	require.Error(t, err)

	// mTLS CA not PEM
	badCA := filepath.Join(dir, "bad.pem")
	require.NoError(t, os.WriteFile(badCA, []byte("not a pem"), 0o600))
	_, err = tlsConfigFromFlags(serverFlags{tlsCert: certPath, tlsKey: keyPath, mtlsCA: badCA})
	require.Error(t, err)

	// broken cert/key pair
	_, err = tlsConfigFromFlags(serverFlags{tlsCert: badCA, tlsKey: badCA})
	require.Error(t, err)
}

func TestCtxWithTimeout(t *testing.T) {
	ctx, cancel := ctxWithTimeout("")
	defer cancel()
	_, ok := ctx.Deadline()
	require.False(t, ok)

	ctx, cancel = ctxWithTimeout("2s")
	defer cancel()
	dl, ok := ctx.Deadline()
	require.True(t, ok)
	require.True(t, time.Until(dl) > time.Second)

	ctx, cancel = ctxWithTimeout("0s")
	defer cancel()
	_, ok = ctx.Deadline()
	require.False(t, ok)
}

func TestHalfCloseWrite(t *testing.T) {
	// TCP conn supports CloseWrite.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, halfCloseWrite(conn))

	// net.Pipe does not implement CloseWrite: must be a no-op.
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	require.NoError(t, halfCloseWrite(a))
}

func TestPrintSnapshotAndDisplayLinkQuality(t *testing.T) {
	tr := linkquality.NewTracker(linkquality.Metadata{Kind: linkquality.EndpointTCP})
	tr.RecordProbe(15*time.Millisecond, nil)
	tr.RecordThroughput(32*1024, 50*time.Millisecond)

	// printSnapshot writes to stderr; just exercise both branches.
	printSnapshot(tr)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { defer close(done); displayLinkQuality(tr, 0, stop) }() // 0 => default interval
	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("displayLinkQuality did not stop")
	}
}

func TestUsage(t *testing.T) {
	usage() // writes to stderr; must not panic
}

// dialCmd happy path: -send through a local SOCKS server to an echo backend.
// Error paths call log.Fatalf/os.Exit and cannot run in-process.
func TestDialCmd_Send(t *testing.T) {
	backendAddr, stopBackend := startCLIBackend(t)
	defer stopBackend()

	listen, stop := startCLIServer(t)
	defer stop()

	dialCmd([]string{
		"-socks", listen,
		"-dest", backendAddr.String(),
		"-send", "ping",
		"-handshake-timeout", "2s",
		"-io-timeout", "1s",
		"-linkquality",
		"-linkquality-interval", "200ms",
	})
}
