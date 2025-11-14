// Package tcp provides helpers to manage SOCKS5 CONNECT tunnels as enriched
// TCP streams. It wraps negotiated connections with ergonomic utilities for
// reads, writes, deadline handling, and bidirectional relays.
package tcp

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/AeonDave/go-s5/client/internal/logging"
)

// Stream wraps a TCP connection negotiated through a SOCKS proxy and offers
// convenience helpers for common stream-oriented operations.
type Stream struct {
	conn                 net.Conn
	logger               logging.Logger
	relayBufPool         sync.Pool
	relayActivityTimeout time.Duration
}

// Option configures the Stream helper.
type Option func(*Stream)

const (
	defaultRelayBufferSize   = 32 * 1024
	defaultRelayActivityIdle = 5 * time.Second
)

// NewStream validates and wraps conn into a Stream helper.
func NewStream(conn net.Conn, opts ...Option) (*Stream, error) {
	if conn == nil {
		return nil, errors.New("nil TCP connection")
	}
	s := &Stream{
		conn:                 conn,
		logger:               logging.NewNop(),
		relayActivityTimeout: defaultRelayActivityIdle,
	}
	s.relayBufPool.New = func() any { return make([]byte, defaultRelayBufferSize) }
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	if s.logger == nil {
		s.logger = logging.NewNop()
	}
	return s, nil
}

// WithLogger installs a logger for relay lifecycle events. Passing nil silences
// all logging.
func WithLogger(l logging.Logger) Option {
	return func(s *Stream) {
		if l == nil {
			s.logger = logging.NewNop()
			return
		}
		s.logger = l
	}
}

// WithRelayBufferSize overrides the copy buffer used by Relay. Size must be
// positive; otherwise the default is used.
func WithRelayBufferSize(size int) Option {
	if size <= 0 {
		size = defaultRelayBufferSize
	}
	return func(s *Stream) {
		s.relayBufPool.New = func() any { return make([]byte, size) }
	}
}

// WithRelayActivityTimeout overrides the idle timeout applied to reads and
// writes while relaying. When set to zero or negative no deadlines are applied
// beyond what the underlying connection already enforces.
func WithRelayActivityTimeout(d time.Duration) Option {
	return func(s *Stream) { s.relayActivityTimeout = d }
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

	parentCtx := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	s.logger.Debugf("tcp relay: start %s <-> %s", safeAddr(s.conn.LocalAddr()), safeAddr(peer.RemoteAddr()))

	results := make(chan relayResult, 2)
	var interruptOnce sync.Once
	interrupt := func(reason string) {
		interruptOnce.Do(func() {
			s.logger.Debugf("tcp relay: interrupt (%s)", reason)
			now := time.Now()
			_ = s.conn.SetDeadline(now)
			_ = peer.SetDeadline(now)
			closeHalf(peer, true)
			closeHalf(peer, false)
			closeHalf(s.conn, true)
			closeHalf(s.conn, false)
		})
	}

	go s.copyLoop(ctx, results, peer, s.conn, directionOutbound)
	go s.copyLoop(ctx, results, s.conn, peer, directionInbound)

	var fatal []error
	parentCanceled := false

	for completed := 0; completed < 2; {
		select {
		case <-parentCtx.Done():
			if !parentCanceled {
				parentCanceled = true
				if err := parentCtx.Err(); err != nil {
					fatal = append(fatal, err)
					s.logger.Debugf("tcp relay: parent context done: %v", err)
				}
				interrupt("context cancellation")
				cancel()
			}
		case res := <-results:
			completed++
			s.logRelayResult(res)
			switch {
			case res.err == nil:
				// noop
			case errors.Is(res.err, io.EOF):
				// Normal closure for that direction.
			case errors.Is(res.err, context.Canceled):
				// ignore derived cancellation triggered by interrupting the loop
			default:
				fatal = append(fatal, res.err)
				cancel()
				interrupt(string(res.direction))
			}
		}
	}

	if len(fatal) == 0 {
		if parentCanceled {
			return parentCtx.Err()
		}
		return nil
	}
	if len(fatal) == 1 {
		return fatal[0]
	}
	return errors.Join(fatal...)
}

type relayDirection string

const (
	directionOutbound relayDirection = "stream->peer"
	directionInbound  relayDirection = "peer->stream"
)

type relayResult struct {
	direction relayDirection
	bytes     int64
	err       error
}

func (s *Stream) copyLoop(ctx context.Context, results chan<- relayResult, dst net.Conn, src net.Conn, direction relayDirection) {
	buf := s.borrowRelayBuffer()
	defer s.releaseRelayBuffer(buf)

	var total int64
	for {
		if err := s.applyReadDeadline(src); err != nil {
			results <- relayResult{direction: direction, bytes: total, err: err}
			return
		}
		n, err := src.Read(buf)
		if n > 0 {
			if err := s.applyWriteDeadline(dst); err != nil {
				results <- relayResult{direction: direction, bytes: total, err: err}
				return
			}
			wn, werr := dst.Write(buf[:n])
			total += int64(wn)
			if werr != nil {
				results <- relayResult{direction: direction, bytes: total, err: werr}
				return
			}
			if wn != n {
				results <- relayResult{direction: direction, bytes: total, err: io.ErrShortWrite}
				return
			}
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					results <- relayResult{direction: direction, bytes: total, err: ctx.Err()}
					return
				default:
					continue
				}
			}
			results <- relayResult{direction: direction, bytes: total, err: err}
			return
		}
		select {
		case <-ctx.Done():
			results <- relayResult{direction: direction, bytes: total, err: ctx.Err()}
			return
		default:
		}
	}
}

func (s *Stream) applyReadDeadline(conn net.Conn) error {
	if conn == nil || s.relayActivityTimeout <= 0 {
		return nil
	}
	return conn.SetReadDeadline(time.Now().Add(s.relayActivityTimeout))
}

func (s *Stream) applyWriteDeadline(conn net.Conn) error {
	if conn == nil || s.relayActivityTimeout <= 0 {
		return nil
	}
	return conn.SetWriteDeadline(time.Now().Add(s.relayActivityTimeout))
}

func (s *Stream) borrowRelayBuffer() []byte {
	if buf, ok := s.relayBufPool.Get().([]byte); ok && buf != nil {
		return buf
	}
	if s.relayBufPool.New != nil {
		if buf, ok := s.relayBufPool.New().([]byte); ok {
			return buf
		}
	}
	return make([]byte, defaultRelayBufferSize)
}

func (s *Stream) releaseRelayBuffer(buf []byte) {
	if buf == nil {
		return
	}
	s.relayBufPool.Put(buf)
}

func (s *Stream) logRelayResult(res relayResult) {
	switch {
	case res.err == nil:
		s.logger.Debugf("tcp relay: %s transferred %d bytes", res.direction, res.bytes)
	case errors.Is(res.err, io.EOF):
		s.logger.Debugf("tcp relay: %s closed after %d bytes (EOF)", res.direction, res.bytes)
	case errors.Is(res.err, context.Canceled):
		s.logger.Debugf("tcp relay: %s canceled after %d bytes", res.direction, res.bytes)
	default:
		s.logger.Errorf("tcp relay: %s failed after %d bytes: %v", res.direction, res.bytes, res.err)
	}
}

func closeHalf(conn net.Conn, write bool) {
	if conn == nil {
		return
	}
	if write {
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		return
	}
	if cr, ok := conn.(interface{ CloseRead() error }); ok {
		_ = cr.CloseRead()
	}
}

func safeAddr(addr net.Addr) string {
	if addr == nil {
		return "<nil>"
	}
	return addr.String()
}
