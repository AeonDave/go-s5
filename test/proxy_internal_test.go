package socks5_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/AeonDave/go-s5/internal/protocol"
	_ "unsafe"
)

//go:linkname mapConnectDialError github.com/AeonDave/go-s5/server.mapConnectDialError
func mapConnectDialError(error) uint8

type fakeNetError struct {
	msg     string
	timeout bool
}

func (f fakeNetError) Error() string   { return f.msg }
func (f fakeNetError) Timeout() bool   { return f.timeout }
func (f fakeNetError) Temporary() bool { return false }

func TestMapConnectDialError(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		expected uint8
	}{
		{name: "nil", err: nil, expected: protocol.RepSuccess},
		{name: "context canceled", err: context.Canceled, expected: protocol.RepTTLExpired},
		{name: "context deadline", err: context.DeadlineExceeded, expected: protocol.RepTTLExpired},
		{name: "net timeout", err: fakeNetError{timeout: true}, expected: protocol.RepTTLExpired},
		{name: "syscall conn refused", err: wrapSyscallError(syscall.ECONNREFUSED), expected: protocol.RepConnectionRefused},
		{name: "syscall net unreachable", err: wrapSyscallError(syscall.ENETUNREACH), expected: protocol.RepNetworkUnreachable},
		{name: "syscall host unreachable", err: wrapSyscallError(syscall.EHOSTUNREACH), expected: protocol.RepHostUnreachable},
		{name: "syscall timed out", err: wrapSyscallError(syscall.ETIMEDOUT), expected: protocol.RepTTLExpired},
		{name: "dns not found", err: &net.DNSError{IsNotFound: true}, expected: protocol.RepHostUnreachable},
		{name: "dns timeout", err: &net.DNSError{IsTimeout: true}, expected: protocol.RepTTLExpired},
		{name: "string refused", err: fakeError("connection refused"), expected: protocol.RepConnectionRefused},
		{name: "string network unreachable", err: fakeError("network is unreachable"), expected: protocol.RepNetworkUnreachable},
		{name: "default host unreachable", err: fakeError("something else"), expected: protocol.RepHostUnreachable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mapConnectDialError(tc.err); got != tc.expected {
				t.Fatalf("mapConnectDialError(%v) = %d, want %d", tc.err, got, tc.expected)
			}
		})
	}
}

type fakeError string

func (f fakeError) Error() string { return string(f) }

func wrapSyscallError(errno syscall.Errno) error {
	return fmt.Errorf("dial failed: %w", &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: &os.SyscallError{Syscall: "connect", Err: errno},
	})
}
