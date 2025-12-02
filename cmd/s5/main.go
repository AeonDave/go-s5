package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/net/proxy"

	"github.com/AeonDave/go-s5/auth"
	"github.com/AeonDave/go-s5/client"
	"github.com/AeonDave/go-s5/linkquality"
	"github.com/AeonDave/go-s5/protocol"
	"github.com/AeonDave/go-s5/server"
)

func usage() {
	_, _ = fmt.Fprintf(os.Stderr, "s5 - SOCKS5 toolkit\n\n")
	_, _ = fmt.Fprintf(os.Stderr, "Usage:\n")
	_, _ = fmt.Fprintf(os.Stderr, "  s5 server [flags]            # start a SOCKS5 server\n")
	_, _ = fmt.Fprintf(os.Stderr, "  s5 dial   [flags]            # connect through a SOCKS5 server to a destination\n\n")
	_, _ = fmt.Fprintf(os.Stderr, "Server flags:\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -listen string            listen address (default :1080)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -user string              username for User/Pass auth (optional)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -pass string              password for User/Pass auth (optional)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -bind-ip string           bind IP for BIND/UDP (optional)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -handshake-timeout string handshake timeout, e.g. 5s (optional)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -tcp-keepalive string     TCP keep-alive period, e.g. 30s (optional)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -tls-cert string          TLS cert file (enables TLS)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -tls-key string           TLS key file\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -mtls-ca string           client CA PEM to require/verify client certs\n\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -upstream string          upstream SOCKS5 (host:port) to chain through (optional)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -upstream-user string     username for upstream SOCKS5 auth (optional)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -upstream-pass string     password for upstream SOCKS5 auth (optional)\n\n")
	_, _ = fmt.Fprintf(os.Stderr, "Dial flags:\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -socks string             SOCKS server address (host:port)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -dest string              final destination (host:port)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -user string              username for User/Pass auth (optional)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -pass string              password for User/Pass auth (optional)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -handshake-timeout string handshake timeout, e.g. 5s (optional)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -io-timeout string        per-request I/O timeout, e.g. 10s (optional)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -linkquality              show live link quality metrics for the session\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -linkquality-interval     interval for link quality updates (default 5s)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -stdio                    pipe stdin->dest and dest->stdout\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -send string              send string once, then print response\n")
}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "server":
		serverCmd(os.Args[2:])
	case "dial":
		dialCmd(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		_, _ = fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func parseDuration(s string) time.Duration {
	if s == "" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		log.Fatalf("invalid duration %q: %v", s, err)
	}
	return d
}

func serverCmd(args []string) {
	cfg := parseServerFlags(args)
	opts, err := serverOptionsFromConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}
	srv := server.New(opts...)
	tlsCfg, err := tlsConfigFromFlags(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if tlsCfg != nil {
		log.Fatalf("%v", srv.ListenAndServeTLS("tcp", cfg.listen, tlsCfg))
		return
	}
	log.Fatalf("%v", srv.ListenAndServe("tcp", cfg.listen))
}

type serverFlags struct {
	listen       string
	user         string
	pass         string
	bindIP       string
	hs           string
	ka           string
	tlsCert      string
	tlsKey       string
	mtlsCA       string
	upstream     string
	upstreamUser string
	upstreamPass string
}

func parseServerFlags(args []string) serverFlags {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", ":1080", "listen address")
	user := fs.String("user", "", "username for auth")
	pass := fs.String("pass", "", "password for auth")
	bindIP := fs.String("bind-ip", "", "bind IP for BIND/UDP")
	hs := fs.String("handshake-timeout", "", "handshake timeout (e.g. 5s)")
	ka := fs.String("tcp-keepalive", "", "TCP keep-alive period (e.g. 30s)")
	tlsCert := fs.String("tls-cert", "", "TLS cert file (enables TLS)")
	tlsKey := fs.String("tls-key", "", "TLS key file")
	mtlsCA := fs.String("mtls-ca", "", "client CA file for mTLS")
	upstream := fs.String("upstream", "", "upstream SOCKS5 (host:port) to chain through")
	upUser := fs.String("upstream-user", "", "username for upstream SOCKS5 auth (optional)")
	upPass := fs.String("upstream-pass", "", "password for upstream SOCKS5 auth (optional)")
	_ = fs.Parse(args)
	return serverFlags{
		listen:       *listen,
		user:         *user,
		pass:         *pass,
		bindIP:       *bindIP,
		hs:           *hs,
		ka:           *ka,
		tlsCert:      *tlsCert,
		tlsKey:       *tlsKey,
		mtlsCA:       *mtlsCA,
		upstream:     *upstream,
		upstreamUser: *upUser,
		upstreamPass: *upPass,
	}
}

func serverOptionsFromConfig(cfg serverFlags) ([]server.Option, error) {
	var opts []server.Option
	opts = append(opts, server.WithLogger(server.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))))
	if cfg.user != "" || cfg.pass != "" {
		opts = append(opts, server.WithCredential(auth.StaticCredentials{cfg.user: cfg.pass}))
	}
	if cfg.bindIP != "" {
		ip := net.ParseIP(cfg.bindIP)
		if ip == nil {
			return nil, fmt.Errorf("invalid bind IP: %s", cfg.bindIP)
		}
		opts = append(opts, server.WithBindIP(ip))
	}
	if d := parseDuration(cfg.hs); d > 0 {
		opts = append(opts, server.WithHandshakeTimeout(d))
	}
	if d := parseDuration(cfg.ka); d > 0 {
		opts = append(opts, server.WithTCPKeepAlive(d))
	}

	if cfg.upstream != "" {
		var authInfo *proxy.Auth
		if cfg.upstreamUser != "" || cfg.upstreamPass != "" {
			authInfo = &proxy.Auth{User: cfg.upstreamUser, Password: cfg.upstreamPass}
		}
		upstream, err := proxy.SOCKS5("tcp", cfg.upstream, authInfo, &net.Dialer{Timeout: 10 * time.Second})
		if err != nil {
			return nil, fmt.Errorf("create upstream socks5 dialer: %w", err)
		}
		dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
			type ctxDialer interface {
				DialContext(context.Context, string, string) (net.Conn, error)
			}
			if d, ok := upstream.(ctxDialer); ok {
				return d.DialContext(ctx, network, addr)
			}
			return upstream.Dial(network, addr)
		}
		opts = append(opts, server.WithDial(dial))
	}
	return opts, nil
}

func tlsConfigFromFlags(cfg serverFlags) (*tls.Config, error) {
	if cfg.tlsCert == "" && cfg.tlsKey == "" && cfg.mtlsCA == "" {
		return nil, nil
	}
	if cfg.tlsCert == "" || cfg.tlsKey == "" {
		return nil, errors.New("-tls-cert and -tls-key are required together")
	}
	cert, err := tls.LoadX509KeyPair(cfg.tlsCert, cfg.tlsKey)
	if err != nil {
		return nil, fmt.Errorf("load TLS cert/key: %w", err)
	}
	cfgTLS := &tls.Config{Certificates: []tls.Certificate{cert}}
	if cfg.mtlsCA != "" {
		caPEM, err := os.ReadFile(cfg.mtlsCA)
		if err != nil {
			return nil, fmt.Errorf("read mTLS CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("parse mTLS CA failed")
		}
		cfgTLS.ClientAuth = tls.RequireAndVerifyClientCert
		cfgTLS.ClientCAs = pool
	}
	return cfgTLS, nil
}

func dialCmd(args []string) {
	fs := flag.NewFlagSet("dial", flag.ExitOnError)
	socks := fs.String("socks", "", "SOCKS server address (host:port)")
	dest := fs.String("dest", "", "final destination (host:port)")
	user := fs.String("user", "", "username for auth")
	pass := fs.String("pass", "", "password for auth")
	hs := fs.String("handshake-timeout", "", "handshake timeout (e.g. 5s)")
	ioTO := fs.String("io-timeout", "", "I/O timeout (e.g. 10s)")
	showLQ := fs.Bool("linkquality", false, "show live link quality metrics for this session")
	lqInterval := fs.Duration("linkquality-interval", 5*time.Second, "interval for link quality updates")
	stdio := fs.Bool("stdio", false, "pipe stdin/stdout")
	send := fs.String("send", "", "send string then print response")
	_ = fs.Parse(args)

	if *socks == "" || *dest == "" {
		_, _ = fmt.Fprintln(os.Stderr, "-socks and -dest are required")
		os.Exit(2)
	}
	// TCP to SOCKS server
	dialStart := time.Now()
	conn, err := net.Dial("tcp", *socks)
	if err != nil {
		log.Fatalf("dial socks: %v", err)
	}

	var tracker *linkquality.Tracker
	if *showLQ {
		tracker = linkquality.NewTracker(linkquality.Metadata{RemoteAddr: *socks, Kind: linkquality.EndpointSOCKS5})
		tracker.RecordProbe(time.Since(dialStart), nil)
		conn = linkquality.WrapConn(conn, tracker)
	}
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	var copts []client.Option
	if d := parseDuration(*hs); d > 0 {
		copts = append(copts, client.WithHandshakeTimeout(d))
	}
	if d := parseDuration(*ioTO); d > 0 {
		copts = append(copts, client.WithIOTimeout(d))
	}
	cli := client.New(copts...)

	var creds *client.Credentials
	if *user != "" || *pass != "" {
		creds = &client.Credentials{Username: *user, Password: *pass}
	}
	ctx, cancel := ctxWithTimeout(*hs)
	defer cancel()
	hsStart := time.Now()
	if _, err = cli.Handshake(ctx, conn, creds); err != nil {
		if tracker != nil {
			tracker.RecordProbe(time.Since(hsStart), err)
		}
		log.Fatalf("handshake: %v", err)
	}
	if tracker != nil {
		tracker.RecordProbe(time.Since(hsStart), nil)
	}
	dst, err := protocol.ParseAddrSpec(*dest)
	if err != nil {
		log.Fatalf("parse dest: %v", err)
	}
	ctx2, cancel2 := ctxWithTimeout(*ioTO)
	defer cancel2()
	connStart := time.Now()
	if _, err = cli.Connect(ctx2, conn, dst); err != nil {
		if tracker != nil {
			tracker.RecordProbe(time.Since(connStart), err)
		}
		log.Fatalf("connect failed")
	}
	if tracker != nil {
		tracker.RecordProbe(time.Since(connStart), nil)
	}

	var stopMetrics chan struct{}
	if tracker != nil {
		stopMetrics = make(chan struct{})
		go displayLinkQuality(tracker, *lqInterval, stopMetrics)
	}

	if *stdio {
		// pipe stdin->conn and conn->stdout
		go func() { _, _ = io.Copy(conn, os.Stdin); _ = halfCloseWrite(conn) }()
		_, _ = io.Copy(os.Stdout, conn)
		if stopMetrics != nil {
			close(stopMetrics)
		}
		return
	}
	if *send != "" {
		if _, err := conn.Write([]byte(*send)); err != nil {
			log.Fatalf("send: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(parseDuration(*ioTO)))
		_, _ = io.Copy(os.Stdout, conn)
		_ = conn.SetReadDeadline(time.Time{})
		if stopMetrics != nil {
			close(stopMetrics)
		}
		return
	}
	fmt.Println("connected (no stdio/send specified)")
	if stopMetrics != nil {
		close(stopMetrics)
	}
}

func ctxWithTimeout(s string) (context.Context, context.CancelFunc) {
	if s == "" {
		return context.Background(), func() {}
	}
	d := parseDuration(s)
	if d <= 0 {
		return context.Background(), func() {}
	}
	return context.WithTimeout(context.Background(), d)
}

func halfCloseWrite(c net.Conn) error {
	type cw interface{ CloseWrite() error }
	if x, ok := c.(cw); ok {
		return x.CloseWrite()
	}
	return nil
}

func displayLinkQuality(tr *linkquality.Tracker, interval time.Duration, stop <-chan struct{}) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	printSnapshot(tr)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			printSnapshot(tr)
		case <-stop:
			return
		}
	}
}

func printSnapshot(tr *linkquality.Tracker) {
	info := tr.ConnectionInfo()
	jit := info.Jitter
	if jit == 0 {
		jit = info.RTT.StdDev
	}
	throughput := "-"
	if info.Throughput.Samples > 0 {
		throughput = fmt.Sprintf("%.1f KB/s (peak %.1f)", info.Throughput.AverageBps/1024, info.Throughput.MaxBps/1024)
	}
	uptime := fmt.Sprintf("%.1f%%", info.UptimeRatio*100)
	latency := "-"
	if info.RTT.Avg > 0 {
		latency = fmt.Sprintf("min/avg/max %s/%s/%s", info.RTT.Min, info.RTT.Avg, info.RTT.Max)
	}
	fmt.Fprintf(os.Stderr, "[linkquality] score=%d | success=%d/%d | uptime=%s\n", info.Composite, info.Success, info.Probes, uptime)
	fmt.Fprintf(os.Stderr, "[linkquality] latency: %s | jitter: %s | throughput: %s\n", latency, jit, throughput)
}
