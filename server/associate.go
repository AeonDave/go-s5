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

func udpFlowKeyFor(src *net.UDPAddr, dst *protocol.AddrSpec) udpFlowKey {
	key := udpFlowKey{src: src.AddrPort()}
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

func (sf *Server) udpAssociateLoop(ctx context.Context, bindLn *net.UDPConn, request *handler.Request) {
	conns := &udpPeerTable{}
	resolvedCache := &sync.Map{}
	buf, put := sf.borrowBuf()
	defer func() {
		put()
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

	for {
		srcAddr, pk, ok := sf.nextValidUDP(bindLn, buf, request)
		if !ok {
			return
		}
		sf.handleUDPDatagram(ctx, bindLn, conns, resolvedCache, srcAddr, pk, request)
	}
}

func (sf *Server) nextValidUDP(bindLn *net.UDPConn, buf []byte, request *handler.Request) (*net.UDPAddr, protocol.Datagram, bool) {
	for {
		n, srcAddr, err := bindLn.ReadFromUDP(buf[:cap(buf)])
		if err != nil {
			if isEOFOrClosed(err) {
				return nil, protocol.Datagram{}, false
			}
			continue
		}
		pk, err := protocol.ParseDatagram(buf[:n])
		if err != nil {
			continue
		}
		if pk.Frag != 0 { // drop fragmented UDP datagrams
			sf.logger.Errorf("drop fragmented UDP datagram: frag=%d from %s", pk.Frag, srcAddr)
			continue
		}
		if !addrMatch(request.DestAddr, srcAddr.IP, srcAddr.Port, false) {
			continue
		}
		return srcAddr, pk, true
	}
}

type resolvedEntry struct {
	addr     protocol.AddrSpec
	lastSeen atomic.Int64
}

func newResolvedEntry(addr protocol.AddrSpec, now int64) *resolvedEntry {
	e := &resolvedEntry{addr: addr}
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

func (sf *Server) handleUDPDatagram(ctx context.Context, bindLn *net.UDPConn, conns *udpPeerTable, resolvedCache *sync.Map, srcAddr *net.UDPAddr, pk protocol.Datagram, request *handler.Request) {
	dstAddr := pk.DstAddr // Value copy: struct assignment in Go creates a copy, not an alias
	now := time.Now().UnixNano()
	var flowKey udpFlowKey
	hasFlowKey := false
	if dstAddr.FQDN != "" {
		flowKey = udpFlowKeyFor(srcAddr, &dstAddr)
		hasFlowKey = true
		_, ip, err := sf.resolver.Resolve(ctx, dstAddr.FQDN)
		if err == nil && ip != nil {
			dstAddr.IP = ip
			dstAddr.AddrType = protocol.AddrTypeFromIP(ip)
			dstAddr.FQDN = ""
			resolvedCache.Store(flowKey, newResolvedEntry(dstAddr, now))
		} else if err != nil {
			sf.logger.Errorf("resolve %s failed: %v", dstAddr.FQDN, err)
			if cached, ok := resolvedCache.Load(flowKey); ok {
				if cachedEntry, ok := cached.(*resolvedEntry); ok {
					dstAddr = cachedEntry.addr
					cachedEntry.lastSeen.Store(now)
				}
			}
		}
	}

	connKey := udpFlowKeyFor(srcAddr, &dstAddr)
	if p, ok := conns.load(connKey); ok {
		if _, err := p.conn.Write(pk.Data); err != nil {
			sf.logger.Errorf("write data to remote server failed, %v", err)
			sf.closeIgnoreErr(nameUDPTarget, p.conn)
			conns.delete(connKey)
			return
		}
		p.lastSeen.Store(time.Now().UnixNano())
		if hasFlowKey {
			if cached, ok := resolvedCache.Load(flowKey); ok {
				if cachedEntry, ok := cached.(*resolvedEntry); ok {
					cachedEntry.lastSeen.Store(time.Now().UnixNano())
				}
			}
		}
		return
	}

	if sf.udpMaxPeers > 0 && conns.len() >= sf.udpMaxPeers {
		return
	}

	dialNets, dialAddr := sf.selectUDPDial(srcAddr, &dstAddr)
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
	srcCopy := *srcAddr
	sf.goFunc(func() { sf.pipeUDPFromTarget(bindLn, conns, connKey, targetNew, header, &srcCopy) })

	if _, err := targetNew.Write(pk.Data); err != nil {
		sf.logger.Errorf("write data to remote server %s failed, %v", targetNew.RemoteAddr().String(), err)
		sf.closeIgnoreErr(nameUDPTarget, targetNew)
		conns.delete(connKey)
		return
	}
}

func (sf *Server) selectUDPDial(srcAddr *net.UDPAddr, dstAddr *protocol.AddrSpec) (networks []string, addr string) {
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
		if srcAddr != nil && srcAddr.IP.To4() != nil {
			networks = []string{"udp4", "udp6"}
		} else {
			networks = []string{"udp6", "udp4"}
		}
	}

	return
}

func (sf *Server) pipeUDPFromTarget(bindLn *net.UDPConn, conns *udpPeerTable, connKey udpFlowKey, target net.Conn, header []byte, srcAddr *net.UDPAddr) {
	rbuf, rput := sf.borrowBuf()
	defer func() {
		sf.closeIgnoreErr(nameUDPTarget, target)
		conns.delete(connKey)
		rput()
	}()
	wbuf, wput := sf.borrowBuf()
	defer wput()

	for {
		readArea := rbuf[:cap(rbuf)]
		n, err := target.Read(readArea)
		if err != nil {
			if isEOFOrClosed(err) {
				return
			}
			sf.logger.Errorf("read data from remote %s failed, %v", target.RemoteAddr().String(), err)
			return
		}
		if p, ok := conns.load(connKey); ok {
			p.lastSeen.Store(time.Now().UnixNano())
		}
		proBuf := wbuf[:0]
		proBuf = append(proBuf, header...)
		proBuf = append(proBuf, readArea[:n]...)
		if _, err := bindLn.WriteTo(proBuf, srcAddr); err != nil {
			sf.logger.Errorf("write data to client %s failed, %v", srcAddr, err)
			return
		}
	}
}

func (sf *Server) drainAssociateControl(bindLn *net.UDPConn, r io.Reader) error {
	b, put := sf.borrowBuf()
	defer put()
	for {
		if _, err := r.Read(b[:cap(b)]); err != nil {
			sf.closeIgnoreErr("udp listener", bindLn)
			if isEOFOrClosed(err) {
				return nil
			}
			return err
		}
	}
}
