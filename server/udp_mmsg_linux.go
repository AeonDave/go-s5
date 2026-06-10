//go:build linux

package server

import (
	"net"
	"net/netip"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// udpBatchConn wraps a *net.UDPConn with recvmmsg/sendmmsg-based batched I/O
// so multiple datagrams move per syscall. ipv4.Message and ipv6.Message are
// type aliases of the same struct, so one message slice serves both families.
type udpBatchConn struct {
	pc4   *ipv4.PacketConn
	pc6   *ipv6.PacketConn
	rmsgs []ipv4.Message
	wmsgs []ipv4.Message
}

func newUDPBatchConn(c *net.UDPConn) *udpBatchConn {
	b := &udpBatchConn{
		rmsgs: make([]ipv4.Message, udpBatchSize),
		wmsgs: make([]ipv4.Message, udpBatchSize),
	}
	if la, ok := c.LocalAddr().(*net.UDPAddr); ok && la.IP.To4() == nil {
		b.pc6 = ipv6.NewPacketConn(c)
	} else {
		b.pc4 = ipv4.NewPacketConn(c)
	}
	for i := range b.rmsgs {
		b.rmsgs[i].Buffers = make([][]byte, 1)
	}
	for i := range b.wmsgs {
		b.wmsgs[i].Buffers = make([][]byte, 1)
	}
	return b
}

func (b *udpBatchConn) read(ms []ipv4.Message) (int, error) {
	if b.pc6 != nil {
		return b.pc6.ReadBatch(ms, 0)
	}
	return b.pc4.ReadBatch(ms, 0)
}

func (b *udpBatchConn) write(ms []ipv4.Message) (int, error) {
	if b.pc6 != nil {
		return b.pc6.WriteBatch(ms, 0)
	}
	return b.pc4.WriteBatch(ms, 0)
}

// readBatch posts len(bufs) buffers in one recvmmsg call and reports how many
// datagrams arrived. sizes[i] receives the datagram length; addrs[i] (when the
// slice is non-nil) receives the source address.
func (b *udpBatchConn) readBatch(bufs [][]byte, sizes []int, addrs []netip.AddrPort) (int, error) {
	ms := b.rmsgs[:len(bufs)]
	for i := range bufs {
		ms[i].Buffers[0] = bufs[i]
	}
	n, err := b.read(ms)
	if err != nil {
		return 0, err
	}
	for i := range n {
		sizes[i] = ms[i].N
		if addrs != nil {
			if ua, ok := ms[i].Addr.(*net.UDPAddr); ok && ua != nil {
				addrs[i] = ua.AddrPort()
			} else {
				addrs[i] = netip.AddrPort{}
			}
		}
	}
	return n, nil
}

// writeBatch sends every packet to addr, batching with sendmmsg and looping on
// partial sends.
func (b *udpBatchConn) writeBatch(packets [][]byte, addr *net.UDPAddr) error {
	sent := 0
	for sent < len(packets) {
		k := 0
		for j := sent; j < len(packets) && k < len(b.wmsgs); j++ {
			b.wmsgs[k].Buffers[0] = packets[j]
			b.wmsgs[k].Addr = addr
			k++
		}
		n, err := b.write(b.wmsgs[:k])
		if err != nil {
			return err
		}
		if n <= 0 {
			n = 1 // defensive: never spin
		}
		sent += n
	}
	return nil
}

// udpTargetReader reads from the per-flow target connection, batching when the
// target is a UDP socket and falling back to single reads otherwise (custom
// dialers may return arbitrary net.Conn implementations).
type udpTargetReader struct {
	bc *udpBatchConn
	c  net.Conn
}

func newUDPTargetReader(c net.Conn) *udpTargetReader {
	if uc, ok := c.(*net.UDPConn); ok {
		return &udpTargetReader{bc: newUDPBatchConn(uc)}
	}
	return &udpTargetReader{c: c}
}

func (r *udpTargetReader) readBatch(bufs [][]byte, sizes []int) (int, error) {
	if r.bc != nil {
		return r.bc.readBatch(bufs, sizes, nil)
	}
	n, err := r.c.Read(bufs[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}
