package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/AeonDave/go-s5/auth"
	client "github.com/AeonDave/go-s5/client"
	"github.com/AeonDave/go-s5/protocol"
	server "github.com/AeonDave/go-s5/server"
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
	_, _ = fmt.Fprintf(os.Stderr, "Dial flags:\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -socks string             SOCKS server address (host:port)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -dest string              final destination (host:port)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -user string              username for User/Pass auth (optional)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -pass string              password for User/Pass auth (optional)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -handshake-timeout string handshake timeout, e.g. 5s (optional)\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -io-timeout string        per-request I/O timeout, e.g. 10s (optional)\n")
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
	_ = fs.Parse(args)

	var opts []server.Option
	// Logger to stdout for visibility
	opts = append(opts, server.WithLogger(server.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))))
	if *user != "" || *pass != "" {
		opts = append(opts, server.WithCredential(auth.StaticCredentials{*user: *pass}))
	}
	if *bindIP != "" {
		ip := net.ParseIP(*bindIP)
		if ip == nil {
			log.Fatalf("invalid bind IP: %s", *bindIP)
		}
		opts = append(opts, server.WithBindIP(ip))
	}
	if d := parseDuration(*hs); d > 0 {
		opts = append(opts, server.WithHandshakeTimeout(d))
	}
	if d := parseDuration(*ka); d > 0 {
		opts = append(opts, server.WithTCPKeepAlive(d))
	}

	s := server.New(opts...)

	// TLS handling
	if *tlsCert != "" || *tlsKey != "" || *mtlsCA != "" {
		if *tlsCert == "" || *tlsKey == "" {
			log.Fatal("-tls-cert and -tls-key are required together")
		}
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			log.Fatalf("load TLS cert/key: %v", err)
		}
		cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
		if *mtlsCA != "" {
			caPEM, err := os.ReadFile(*mtlsCA)
			if err != nil {
				log.Fatalf("read mTLS CA: %v", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				log.Fatal("parse mTLS CA failed")
			}
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
			cfg.ClientCAs = pool
		}
		log.Fatalf("%v", s.ListenAndServeTLS("tcp", *listen, cfg))
		return
	}
	log.Fatalf("%v", s.ListenAndServe("tcp", *listen))
}

func dialCmd(args []string) {
	fs := flag.NewFlagSet("dial", flag.ExitOnError)
	socks := fs.String("socks", "", "SOCKS server address (host:port)")
	dest := fs.String("dest", "", "final destination (host:port)")
	user := fs.String("user", "", "username for auth")
	pass := fs.String("pass", "", "password for auth")
	hs := fs.String("handshake-timeout", "", "handshake timeout (e.g. 5s)")
	ioTO := fs.String("io-timeout", "", "I/O timeout (e.g. 10s)")
	stdio := fs.Bool("stdio", false, "pipe stdin/stdout")
	send := fs.String("send", "", "send string then print response")
	_ = fs.Parse(args)

	if *socks == "" || *dest == "" {
		_, _ = fmt.Fprintln(os.Stderr, "-socks and -dest are required")
		os.Exit(2)
	}
	// TCP to SOCKS server
	conn, err := net.Dial("tcp", *socks)
	if err != nil {
		log.Fatalf("dial socks: %v", err)
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
	if _, err = cli.Handshake(ctx, conn, creds); err != nil {
		log.Fatalf("handshake: %v", err)
	}
	dst, err := protocol.ParseAddrSpec(*dest)
	if err != nil {
		log.Fatalf("parse dest: %v", err)
	}
	ctx2, cancel2 := ctxWithTimeout(*ioTO)
	defer cancel2()
	if _, err = cli.Connect(ctx2, conn, dst); err != nil {
		log.Fatalf("connect: %v", err)
	}

	if *stdio {
		// pipe stdin->conn and conn->stdout
		go func() { _, _ = io.Copy(conn, os.Stdin); _ = halfCloseWrite(conn) }()
		_, _ = io.Copy(os.Stdout, conn)
		return
	}
	if *send != "" {
		if _, err := conn.Write([]byte(*send)); err != nil {
			log.Fatalf("send: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(parseDuration(*ioTO)))
		_, _ = io.Copy(os.Stdout, conn)
		_ = conn.SetReadDeadline(time.Time{})
		return
	}
	fmt.Println("connected (no stdio/send specified)")
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
