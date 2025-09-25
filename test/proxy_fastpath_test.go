package socks5_test

import (
	"bytes"
	socks5 "go-s5"
	"io"
	"testing"
)

// Writer implementing ReaderFrom and closeWriter
type rfWriter struct {
	bytes.Buffer
	rfCalled bool
	cwCalled bool
}

func (w *rfWriter) ReadFrom(r io.Reader) (int64, error) {
	w.rfCalled = true
	return io.Copy(&w.Buffer, r)
}

func (w *rfWriter) CloseWrite() error { w.cwCalled = true; return nil }

// Reader implementing WriteTo
type wtReader struct {
	data     []byte
	wtCalled bool
}

func (r *wtReader) Read(p []byte) (int, error) { return bytes.NewReader(r.data).Read(p) }
func (r *wtReader) WriteTo(w io.Writer) (int64, error) {
	r.wtCalled = true
	n, err := w.Write(r.data)
	return int64(n), err
}

// Writer without ReaderFrom but with CloseWrite
type cwWriter struct {
	bytes.Buffer
	cwCalled bool
}

func (w *cwWriter) CloseWrite() error { w.cwCalled = true; return nil }

func TestProxy_FastPath_ReadFrom(t *testing.T) {
	srv := socks5.NewServer()
	w := &rfWriter{}
	src := bytes.NewReader([]byte("hello"))
	if err := srv.Proxy(w, src); err != nil {
		t.Fatalf("proxy error: %v", err)
	}
	if !w.rfCalled {
		t.Fatalf("expected ReadFrom to be used")
	}
	if !w.cwCalled {
		t.Fatalf("expected CloseWrite to be called")
	}
	if got := w.String(); got != "hello" {
		t.Fatalf("unexpected copy: %q", got)
	}
}

func TestProxy_FastPath_WriteTo(t *testing.T) {
	srv := socks5.NewServer()
	r := &wtReader{data: []byte("hello")}
	w := &cwWriter{}
	if err := srv.Proxy(w, r); err != nil {
		t.Fatalf("proxy error: %v", err)
	}
	if !r.wtCalled {
		t.Fatalf("expected WriteTo to be used")
	}
	if !w.cwCalled {
		t.Fatalf("expected CloseWrite to be called")
	}
	if got := w.String(); got != "hello" {
		t.Fatalf("unexpected copy: %q", got)
	}
}

func TestProxy_Fallback_CopyBuffer(t *testing.T) {
	srv := socks5.NewServer()
	var w bytes.Buffer
	src := bytes.NewReader([]byte("hello"))
	if err := srv.Proxy(&w, src); err != nil {
		t.Fatalf("proxy error: %v", err)
	}
	if got := w.String(); got != "hello" {
		t.Fatalf("unexpected copy: %q", got)
	}
}

// Reader that supports CloseRead to verify it gets called
type crReader struct {
	data     []byte
	crCalled bool
}

func (r *crReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
func (r *crReader) CloseRead() error { r.crCalled = true; return nil }

func TestProxy_Fallback_Closes(t *testing.T) {
	srv := socks5.NewServer()
	r := &crReader{data: []byte("hello")}
	w := &cwWriter{}
	if err := srv.Proxy(w, r); err != nil {
		t.Fatalf("proxy error: %v", err)
	}
	if !w.cwCalled {
		t.Fatalf("expected CloseWrite to be called")
	}
	if !r.crCalled {
		t.Fatalf("expected CloseRead to be called")
	}
	if got := w.String(); got != "hello" {
		t.Fatalf("unexpected copy: %q", got)
	}
}
