package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/internal/protocol"
)

// udpBatchSize is how many datagrams move per syscall on platforms with
// recvmmsg/sendmmsg support (Linux). Elsewhere the same code paths run with an
// effective batch of one. Each batch slot pins one pooled buffer for the
// lifetime of its loop.
const udpBatchSize = 8

// udpBatchInitial is how many buffers a loop posts before any read saturates.
// Sparse flows (e.g. DNS-style query/response) never pin more than this; the
// posted set doubles toward udpBatchSize only under sustained bursts.
const udpBatchInitial = 2

// udpBatchBufs manages the pooled buffers posted to batched reads, growing
// them adaptively so idle flows stay cheap and hot flows reach full batching.
type udpBatchBufs struct {
	sf   *Server
	bufs [][]byte
	puts []func()
}

func (sf *Server) newUDPBatchBufs() *udpBatchBufs {
	b := &udpBatchBufs{sf: sf}
	b.growTo(udpBatchInitial)
	return b
}

func (b *udpBatchBufs) growTo(n int) {
	for len(b.bufs) < n && len(b.bufs) < udpBatchSize {
		raw, put := b.sf.borrowBuf()
		b.bufs = append(b.bufs, raw[:cap(raw)])
		b.puts = append(b.puts, put)
	}
}

// onRead doubles the posted set when the last read filled every buffer,
// reporting whether the set grew so callers can refresh derived views.
func (b *udpBatchBufs) onRead(n int) bool {
	if n == len(b.bufs) && len(b.bufs) < udpBatchSize {
		b.growTo(len(b.bufs) * 2)
		return true
	}
	return false
}

func (b *udpBatchBufs) release() {
	for _, put := range b.puts {
		put()
	}
}

// udpResolveTTL bounds how long a per-flow FQDN resolution is reused before a
// fresh lookup. Within the TTL, datagrams skip the resolver entirely.
const udpResolveTTL = 30 * time.Second

type udpPeer struct {
	conn     net.Conn
	lastSeen atomic.Int64 // unix nano
}

// udpFlowKey identifies a client->destination UDP flow without allocating
// per-packet strings. For IP destinations dst carries the resolved address;
// for unresolved FQDN flows fqdn is set and dst holds only the port.
type udpFlowKey struct {
	src  netip.AddrPort
	dst  netip.AddrPort
	fqdn string
}

func udpFlowKeyFor(src netip.AddrPort, dst *protocol.AddrSpec) udpFlowKey {
	key := udpFlowKey{src: src}
	if a, ok := netip.AddrFromSlice(dst.IP); ok {
		key.dst = netip.AddrPortFrom(a.Unmap(), uint16(dst.Port))
	} else {
		key.fqdn = dst.FQDN
		key.dst = netip.AddrPortFrom(netip.Addr{}, uint16(dst.Port))
	}
	return key
}

// udpPeerTable wraps sync.Map with an O(1) size counter so per-datagram peer
// limit checks do not scan the whole table.
type udpPeerTable struct {
	peers sync.Map
	count atomic.Int64
}

func (t *udpPeerTable) load(key udpFlowKey) (*udpPeer, bool) {
	v, ok := t.peers.Load(key)
	if !ok {
		return nil, false
	}
	return v.(*udpPeer), true
}

func (t *udpPeerTable) store(key udpFlowKey, p *udpPeer) {
	t.peers.Store(key, p)
	t.count.Add(1)
}

// delete removes key and decrements the counter only when the entry was still
// present, so concurrent double-deletes stay balanced.
func (t *udpPeerTable) delete(key udpFlowKey) {
	if _, ok := t.peers.LoadAndDelete(key); ok {
		t.count.Add(-1)
	}
}

func (t *udpPeerTable) len() int { return int(t.count.Load()) }

func (t *udpPeerTable) rangeAll(f func(key udpFlowKey, p *udpPeer) bool) {
	t.peers.Range(func(k, v any) bool {
		return f(k.(udpFlowKey), v.(*udpPeer))
	})
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

func (sf *Server) handleAssociate(ctx context.Context, writer io.Writer, request *handler.Request) error {
	udpAddr := sf.udpBindAddrForAssociate(request)
	bindLn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		if err := SendReply(writer, protocol.RepServerFailure, nil); err != nil {
			return fmt.Errorf(fmtFailedSendReply, err)
		}
		return fmt.Errorf("listen udp failed, %v", err)
	}

	if err = SendReply(writer, protocol.RepSuccess, bindLn.LocalAddr()); err != nil {
		return fmt.Errorf(fmtFailedSendReply, err)
	}

	sf.goFunc(func() { sf.udpAssociateLoop(ctx, bindLn, request) })

	return sf.drainAssociateControl(bindLn, request.Reader)
}

func (sf *Server) udpBindAddrForAssociate(request *handler.Request) *net.UDPAddr {
	if sf.useBindIpBaseResolveAsUdpAddr {
		if sf.bindIP != nil {
			return &net.UDPAddr{IP: sf.bindIP, Port: 0}
		}
		return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}
	if tcpLocal, ok := request.LocalAddr.(*net.TCPAddr); ok && tcpLocal != nil {
		return &net.UDPAddr{IP: tcpLocal.IP, Port: 0}
	}
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

// udpSourceMatcher precomputes the expected-source check so the per-datagram
// hot path compares netip values instead of converting net.IP every packet.
func udpSourceMatcher(expect *protocol.AddrSpec) func(netip.AddrPort) bool {
	if expect == nil {
		return func(netip.AddrPort) bool { return true }
	}
	var expectAddr netip.Addr
	if a, ok := netip.AddrFromSlice(expect.IP); ok {
		expectAddr = a.Unmap()
	}
	expectPort := expect.Port
	return func(src netip.AddrPort) bool {
		if expectAddr.IsValid() && !expectAddr.IsUnspecified() && expectAddr != src.Addr().Unmap() {
			return false
		}
		return expectPort == 0 || expectPort == int(src.Port())
	}
}

func (sf *Server) udpAssociateLoop(ctx context.Context, bindLn *net.UDPConn, request *handler.Request) {
	conns := &udpPeerTable{}
	resolvedCache := &sync.Map{}

	bb := sf.newUDPBatchBufs()
	sizes := make([]int, udpBatchSize)
	addrs := make([]netip.AddrPort, udpBatchSize)
	bc := newUDPBatchConn(bindLn)

	defer func() {
		bb.release()
		sf.closeIgnoreErr("udp listener", bindLn)
		conns.rangeAll(func(_ udpFlowKey, p *udpPeer) bool {
			sf.closeIgnoreErr(nameUDPTarget, p.conn)
			return true
		})
	}()

	stop := sf.startUDPIdleReaper(conns, resolvedCache)
	if stop != nil {
		defer stop()
	}

	srcOK := udpSourceMatcher(request.DestAddr)

	for {
		n, err := bc.readBatch(bb.bufs, sizes, addrs)
		if err != nil {
			if isEOFOrClosed(err) {
				return
			}
			continue
		}
		for i := range n {
			pk, perr := protocol.ParseDatagram(bb.bufs[i][:sizes[i]])
			if perr != nil {
				continue
			}
			if pk.Frag != 0 { // drop fragmented UDP datagrams
				sf.logger.Errorf("drop fragmented UDP datagram: frag=%d from %s", pk.Frag, addrs[i])
				continue
			}
			if !srcOK(addrs[i]) {
				continue
			}
			sf.handleUDPDatagram(ctx, bindLn, conns, resolvedCache, addrs[i], pk, request)
		}
		bb.onRead(n)
	}
}

type resolvedEntry struct {
	addr       protocol.AddrSpec
	resolvedAt int64 // unix nano, immutable after creation
	lastSeen   atomic.Int64
}

func newResolvedEntry(addr protocol.AddrSpec, now int64) *resolvedEntry {
	e := &resolvedEntry{addr: addr, resolvedAt: now}
	e.lastSeen.Store(now)
	return e
}

func (sf *Server) startUDPIdleReaper(conns *udpPeerTable, resolvedCache *sync.Map) func() {
	if sf.udpIdleTimeout <= 0 {
		return nil
	}
	stopCh := make(chan struct{})
	ticker := time.NewTicker(minDuration(sf.udpIdleTimeout/2, 30*time.Second))
	go func() {
		for {
			select {
			case <-ticker.C:
				deadline := time.Now().Add(-sf.udpIdleTimeout).UnixNano()
				conns.rangeAll(func(key udpFlowKey, p *udpPeer) bool {
					if p.lastSeen.Load() < deadline {
						sf.closeIgnoreErr("udp target idle", p.conn)
						conns.delete(key)
					}
					return true
				})
				if resolvedCache != nil {
					resolvedCache.Range(func(key, value any) bool {
						if entry, ok := value.(*resolvedEntry); ok {
							if entry.lastSeen.Load() < deadline {
								resolvedCache.Delete(key)
							}
						}
						return true
					})
				}
			case <-stopCh:
				return
			}
		}
	}()
	return func() { ticker.Stop(); close(stopCh) }
}

// resolveUDPDest resolves an FQDN destination, consulting the per-flow cache
// first: within udpResolveTTL no resolver call is made at all, and on resolver
// failure a stale entry keeps the flow alive (DNS blips don't drop traffic).
func (sf *Server) resolveUDPDest(ctx context.Context, resolvedCache *sync.Map, flowKey udpFlowKey, dstAddr protocol.AddrSpec, now int64) protocol.AddrSpec {
	if cached, ok := resolvedCache.Load(flowKey); ok {
		if entry, ok := cached.(*resolvedEntry); ok && now-entry.resolvedAt < int64(udpResolveTTL) {
			entry.lastSeen.Store(now)
			return entry.addr
		}
	}
	_, ip, err := sf.resolver.Resolve(ctx, dstAddr.FQDN)
	if err == nil && ip != nil {
		dstAddr.IP = ip
		dstAddr.AddrType = protocol.AddrTypeFromIP(ip)
		dstAddr.FQDN = ""
		resolvedCache.Store(flowKey, newResolvedEntry(dstAddr, now))
		return dstAddr
	}
	if err != nil {
		sf.logger.Errorf("resolve %s failed: %v", dstAddr.FQDN, err)
		if cached, ok := resolvedCache.Load(flowKey); ok {
			if entry, ok := cached.(*resolvedEntry); ok {
				entry.lastSeen.Store(now)
				return entry.addr
			}
		}
	}
	return dstAddr
}

func (sf *Server) handleUDPDatagram(ctx context.Context, bindLn *net.UDPConn, conns *udpPeerTable, resolvedCache *sync.Map, srcAddr netip.AddrPort, pk protocol.Datagram, request *handler.Request) {
	dstAddr := pk.DstAddr // Value copy: struct assignment in Go creates a copy, not an alias
	now := time.Now().UnixNano()
	if dstAddr.FQDN != "" {
		flowKey := udpFlowKeyFor(srcAddr, &dstAddr)
		dstAddr = sf.resolveUDPDest(ctx, resolvedCache, flowKey, dstAddr, now)
	}

	connKey := udpFlowKeyFor(srcAddr, &dstAddr)
	if p, ok := conns.load(connKey); ok {
		if _, err := p.conn.Write(pk.Data); err != nil {
			sf.logger.Errorf("write data to remote server failed, %v", err)
			sf.closeIgnoreErr(nameUDPTarget, p.conn)
			conns.delete(connKey)
			return
		}
		p.lastSeen.Store(now)
		return
	}

	if sf.udpMaxPeers > 0 && conns.len() >= sf.udpMaxPeers {
		return
	}

	dialNets, dialAddr := selectUDPDial(srcAddr, &dstAddr)
	var targetNew net.Conn
	var err error
	for _, dialNet := range dialNets {
		targetNew, err = sf.dialOut(ctx, dialNet, dialAddr, request)
		if err == nil {
			break
		}
	}
	if err != nil {
		sf.logger.Errorf("connect to %v failed, %v", pk.DstAddr, err)
		return
	}

	p := &udpPeer{conn: targetNew}
	p.lastSeen.Store(time.Now().UnixNano())
	conns.store(connKey, p)

	header := pk.Header()
	clientAddr := net.UDPAddrFromAddrPort(srcAddr)
	sf.goFunc(func() { sf.pipeUDPFromTarget(bindLn, conns, connKey, targetNew, header, clientAddr) })

	if _, err := targetNew.Write(pk.Data); err != nil {
		sf.logger.Errorf("write data to remote server %s failed, %v", targetNew.RemoteAddr().String(), err)
		sf.closeIgnoreErr(nameUDPTarget, targetNew)
		conns.delete(connKey)
		return
	}
}

func selectUDPDial(srcAddr netip.AddrPort, dstAddr *protocol.AddrSpec) (networks []string, addr string) {
	addr = dstAddr.String()
	if dstAddr.FQDN != "" && len(dstAddr.IP) == 0 {
		addr = net.JoinHostPort(dstAddr.FQDN, strconv.Itoa(dstAddr.Port))
	}

	switch dstAddr.AddrType {
	case protocol.ATYPIPv4:
		networks = []string{"udp4"}
	case protocol.ATYPIPv6:
		networks = []string{"udp6"}
	default:
		if srcAddr.Addr().Unmap().Is4() {
			networks = []string{"udp4", "udp6"}
		} else {
			networks = []string{"udp6", "udp4"}
		}
	}

	return
}

// pipeUDPFromTarget relays target->client. The fixed SOCKS UDP header for the
// flow is pre-written into the head of every batch buffer and reads land
// directly after it, so each relayed datagram is assembled without copying the
// payload. On Linux, reads from the target and writes to the client batch via
// recvmmsg/sendmmsg.
func (sf *Server) pipeUDPFromTarget(bindLn *net.UDPConn, conns *udpPeerTable, connKey udpFlowKey, target net.Conn, header []byte, clientAddr *net.UDPAddr) {
	hlen := len(header)
	bb := sf.newUDPBatchBufs()
	payloads := make([][]byte, 0, udpBatchSize)
	packets := make([][]byte, udpBatchSize)
	// syncViews pre-writes the flow's fixed SOCKS UDP header into each newly
	// posted buffer and exposes the area after it as the read target.
	syncViews := func() {
		for i := len(payloads); i < len(bb.bufs); i++ {
			copy(bb.bufs[i], header)
			payloads = append(payloads, bb.bufs[i][hlen:])
		}
	}
	syncViews()
	defer func() {
		sf.closeIgnoreErr(nameUDPTarget, target)
		conns.delete(connKey)
		bb.release()
	}()

	tr := newUDPTargetReader(target)
	out := newUDPBatchConn(bindLn)
	sizes := make([]int, udpBatchSize)

	for {
		n, err := tr.readBatch(payloads, sizes)
		if err != nil {
			if !isEOFOrClosed(err) {
				sf.logger.Errorf("read data from remote %s failed, %v", target.RemoteAddr().String(), err)
			}
			return
		}
		if n <= 0 {
			continue
		}
		if p, ok := conns.load(connKey); ok {
			p.lastSeen.Store(time.Now().UnixNano())
		}
		for i := range n {
			packets[i] = bb.bufs[i][:hlen+sizes[i]]
		}
		if err := out.writeBatch(packets[:n], clientAddr); err != nil {
			sf.logger.Errorf("write data to client %s failed, %v", clientAddr, err)
			return
		}
		if bb.onRead(n) {
			syncViews()
		}
	}
}

// drainAssociateControl keeps reading the TCP control connection until the
// client closes it. RFC 1928 defines no payload on this channel, so a tiny
// stack buffer suffices: no pooled buffer is pinned per association.
func (sf *Server) drainAssociateControl(bindLn *net.UDPConn, r io.Reader) error {
	var b [128]byte
	for {
		if _, err := r.Read(b[:]); err != nil {
			sf.closeIgnoreErr("udp listener", bindLn)
			if isEOFOrClosed(err) {
				return nil
			}
			return err
		}
	}
}
