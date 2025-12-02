package socks5_test

import (
	"bytes"
	"io"
	"testing"
	"time"

	_ "unsafe"

	"github.com/AeonDave/go-s5/server"
)

//go:linkname proxyDuplex github.com/AeonDave/go-s5/server.(*Server).proxyDuplex
func proxyDuplex(*server.Server, io.Writer, io.Reader, io.Writer, io.Reader) error

func TestProxyDuplex_WaitsForBothDirections(t *testing.T) {
	srv := server.New()

	aSrcR, aSrcW := io.Pipe()
	bSrcR, bSrcW := io.Pipe()

	var aDst bytes.Buffer
	var bDst bytes.Buffer

	done := make(chan error, 1)
	go func() {
		done <- proxyDuplex(srv, &aDst, aSrcR, &bDst, bSrcR)
	}()

	go func() {
		_, _ = aSrcW.Write([]byte("left"))
		_ = aSrcW.Close()
	}()

	select {
	case err := <-done:
		t.Fatalf("proxyDuplex returned before second leg finished: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	go func() {
		_, _ = bSrcW.Write([]byte("right"))
		_ = bSrcW.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("proxyDuplex error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("proxyDuplex did not finish after second leg completed")
	}

	if got := aDst.String(); got != "left" {
		t.Fatalf("unexpected left payload: %q", got)
	}
	if got := bDst.String(); got != "right" {
		t.Fatalf("unexpected right payload: %q", got)
	}
}
