//go:build !linux

package server

import (
	"net"
	"net/netip"
)

// udpBatchConn is the portable fallback: one datagram per call using the
// allocation-free AddrPort read/write methods. The shape matches the Linux
// recvmmsg/sendmmsg implementation so callers share a single code path.
type udpBatchConn struct {
	c *net.UDPConn
}

func newUDPBatchConn(c *net.UDPConn) *udpBatchConn {
	return &udpBatchConn{c: c}
}

// readBatch reads a single datagram into bufs[0].
func (b *udpBatchConn) readBatch(bufs [][]byte, sizes []int, addrs []netip.AddrPort) (int, error) {
	n, ap, err := b.c.ReadFromUDPAddrPort(bufs[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	if addrs != nil {
		addrs[0] = ap
	}
	return 1, nil
}

// writeBatch sends every packet to addr with one syscall each.
func (b *udpBatchConn) writeBatch(packets [][]byte, addr *net.UDPAddr) error {
	for _, p := range packets {
		if _, err := b.c.WriteToUDP(p, addr); err != nil {
			return err
		}
	}
	return nil
}

// udpTargetReader reads from the per-flow target connection one datagram at a
// time on platforms without mmsg support.
type udpTargetReader struct {
	c net.Conn
}

func newUDPTargetReader(c net.Conn) *udpTargetReader {
	return &udpTargetReader{c: c}
}

func (r *udpTargetReader) readBatch(bufs [][]byte, sizes []int) (int, error) {
	n, err := r.c.Read(bufs[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}
