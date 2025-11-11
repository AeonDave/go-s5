// Package tcp provides helpers to manage SOCKS5 CONNECT tunnels as enriched
// TCP streams. It wraps negotiated connections with ergonomic utilities for
// reads, writes, deadline handling, and bidirectional relays.
package tcp

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

// Stream wraps a TCP connection negotiated through a SOCKS proxy and offers
// convenience helpers for common stream-oriented operations.
type Stream struct {
	conn net.Conn
}

// NewStream validates and wraps conn into a Stream helper.
func NewStream(conn net.Conn) (*Stream, error) {
	if conn == nil {
		return nil, errors.New("nil TCP connection")
	}
	return &Stream{conn: conn}, nil
}

// Conn returns the underlying TCP connection.
func (s *Stream) Conn() net.Conn {
	if s == nil {
		return nil
	}
	return s.conn
}

// Close closes the underlying TCP connection.
func (s *Stream) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

// LocalAddr returns the local address for the underlying connection.
func (s *Stream) LocalAddr() net.Addr {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

// RemoteAddr returns the remote address for the underlying connection.
func (s *Stream) RemoteAddr() net.Addr {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.RemoteAddr()
}

// SetDeadline applies a deadline to the underlying connection.
func (s *Stream) SetDeadline(t time.Time) error {
	if s == nil || s.conn == nil {
		return errors.New("invalid TCP stream")
	}
	return s.conn.SetDeadline(t)
}

// SetReadDeadline applies a read deadline to the underlying connection.
func (s *Stream) SetReadDeadline(t time.Time) error {
	if s == nil || s.conn == nil {
		return errors.New("invalid TCP stream")
	}
	return s.conn.SetReadDeadline(t)
}

// SetWriteDeadline applies a write deadline to the underlying connection.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	if s == nil || s.conn == nil {
		return errors.New("invalid TCP stream")
	}
	return s.conn.SetWriteDeadline(t)
}

// Write forwards payload to the remote peer.
func (s *Stream) Write(b []byte) (int, error) {
	if s == nil || s.conn == nil {
		return 0, errors.New("invalid TCP stream")
	}
	return s.conn.Write(b)
}

// WriteAll writes the full payload, retrying short writes until all bytes have
// been sent or an error occurs.
func (s *Stream) WriteAll(b []byte) error {
	if s == nil || s.conn == nil {
		return errors.New("invalid TCP stream")
	}
	for len(b) > 0 {
		n, err := s.conn.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

// WriteString writes string payload to the connection.
func (s *Stream) WriteString(str string) (int, error) {
	if s == nil || s.conn == nil {
		return 0, errors.New("invalid TCP stream")
	}
	return io.WriteString(s.conn, str)
}

// Read reads up to len(b) bytes from the stream.
func (s *Stream) Read(b []byte) (int, error) {
	if s == nil || s.conn == nil {
		return 0, errors.New("invalid TCP stream")
	}
	return s.conn.Read(b)
}

// ReadFull reads exactly len(b) bytes into b. It returns io.ErrUnexpectedEOF
// if the stream closes before all bytes are read.
func (s *Stream) ReadFull(b []byte) error {
	if s == nil || s.conn == nil {
		return errors.New("invalid TCP stream")
	}
	_, err := io.ReadFull(s.conn, b)
	return err
}

// CopyTo copies the stream contents into dst until EOF or error.
func (s *Stream) CopyTo(dst io.Writer) (int64, error) {
	if s == nil || s.conn == nil {
		return 0, errors.New("invalid TCP stream")
	}
	if dst == nil {
		return 0, errors.New("nil destination writer")
	}
	return io.Copy(dst, s.conn)
}

// CopyFrom copies data from src into the stream until EOF or error.
func (s *Stream) CopyFrom(src io.Reader) (int64, error) {
	if s == nil || s.conn == nil {
		return 0, errors.New("invalid TCP stream")
	}
	if src == nil {
		return 0, errors.New("nil source reader")
	}
	return io.Copy(s.conn, src)
}

// Relay proxies traffic bidirectionally between the stream and peer until the
// context is done or either side errors. The first error encountered is
// returned. Both connections have their deadlines forced to time.Now() when the
// relay terminates to unblock pending operations.
func (s *Stream) Relay(ctx context.Context, peer net.Conn) error {
	if s == nil || s.conn == nil {
		return errors.New("invalid TCP stream")
	}
	if peer == nil {
		return errors.New("nil peer connection")
	}

	errCh := make(chan error, 2)
	pipe := func(dst net.Conn, src net.Conn) {
		_, err := io.Copy(dst, src)
		errCh <- err
	}

	go pipe(peer, s.conn)
	go pipe(s.conn, peer)

	select {
	case <-ctx.Done():
		_ = s.conn.SetDeadline(time.Now())
		_ = peer.SetDeadline(time.Now())
		return ctx.Err()
	case err := <-errCh:
		_ = s.conn.SetDeadline(time.Now())
		_ = peer.SetDeadline(time.Now())
		return err
	}
}
