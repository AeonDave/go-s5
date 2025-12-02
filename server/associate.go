package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/internal/protocol"
)

type udpPeer struct {
	conn     net.Conn
	lastSeen int64 // unix nano
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

//goland:noinspection GoUnusedFunction
func udpNetworkFor(ip net.IP) string {
	if len(ip) == 0 {
		return "udp"
	}
	if ip.To4() != nil {
		return "udp4"
	}
	if ip.To16() != nil {
		return "udp6"
	}
	return "udp"
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
	conns := &sync.Map{}
	resolvedCache := &sync.Map{}
	buf, put := sf.borrowBuf()
	defer func() {
		put()
		sf.closeIgnoreErr("udp listener", bindLn)
		conns.Range(func(key, value any) bool {
			if p, ok := value.(*udpPeer); ok && p != nil {
				sf.closeIgnoreErr(nameUDPTarget, p.conn)
			} else {
				sf.logger.Errorf("conns has illegal item %v:%v", key, value)
			}
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
	lastSeen int64
}

func (sf *Server) startUDPIdleReaper(conns *sync.Map, resolvedCache *sync.Map) func() {
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
				conns.Range(func(key, value any) bool {
					if p, ok := value.(*udpPeer); ok {
						if atomic.LoadInt64(&p.lastSeen) < deadline {
							sf.closeIgnoreErr("udp target idle", p.conn)
							conns.Delete(key)
						}
					}
					return true
				})
				if resolvedCache != nil {
					resolvedCache.Range(func(key, value any) bool {
						if entry, ok := value.(*resolvedEntry); ok {
							if atomic.LoadInt64(&entry.lastSeen) < deadline {
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

func (sf *Server) handleUDPDatagram(ctx context.Context, bindLn *net.UDPConn, conns *sync.Map, resolvedCache *sync.Map, srcAddr *net.UDPAddr, pk protocol.Datagram, request *handler.Request) {
	dstAddr := pk.DstAddr // Value copy: struct assignment in Go creates a copy, not an alias
	now := time.Now().UnixNano()
	var flowKey string
	if dstAddr.FQDN != "" {
		flowKey = srcAddr.String() + "--" + dstAddr.FQDN + ":" + strconv.Itoa(dstAddr.Port)
		_, ip, err := sf.resolver.Resolve(ctx, dstAddr.FQDN)
		if err == nil && ip != nil {
			dstAddr.IP = ip
			dstAddr.AddrType = protocol.AddrTypeFromIP(ip)
			dstAddr.FQDN = ""
			resolvedCache.Store(flowKey, &resolvedEntry{addr: dstAddr, lastSeen: now})
		} else if err != nil {
			sf.logger.Errorf("resolve %s failed: %v", dstAddr.FQDN, err)
			if cached, ok := resolvedCache.Load(flowKey); ok {
				if cachedEntry, ok := cached.(*resolvedEntry); ok {
					dstAddr = cachedEntry.addr
					atomic.StoreInt64(&cachedEntry.lastSeen, now)
				}
			}
		}
	}

	connKey := srcAddr.String() + "--" + dstAddr.String()
	if v, ok := conns.Load(connKey); ok {
		p := v.(*udpPeer)
		if _, err := p.conn.Write(pk.Data); err != nil {
			sf.logger.Errorf("write data to remote server failed, %v", err)
			sf.closeIgnoreErr(nameUDPTarget, p.conn)
			conns.Delete(connKey)
			return
		}
		atomic.StoreInt64(&p.lastSeen, time.Now().UnixNano())
		if flowKey != "" {
			if cached, ok := resolvedCache.Load(flowKey); ok {
				if cachedEntry, ok := cached.(*resolvedEntry); ok {
					atomic.StoreInt64(&cachedEntry.lastSeen, time.Now().UnixNano())
				}
			}
		}
		return
	}

	if sf.reachUDPMaxPeers(conns) {
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
	atomic.StoreInt64(&p.lastSeen, time.Now().UnixNano())
	conns.Store(connKey, p)

	header := pk.Header()
	srcCopy := *srcAddr
	sf.goFunc(func() { sf.pipeUDPFromTarget(bindLn, conns, connKey, targetNew, header, &srcCopy) })

	if _, err := targetNew.Write(pk.Data); err != nil {
		sf.logger.Errorf("write data to remote server %s failed, %v", targetNew.RemoteAddr().String(), err)
		sf.closeIgnoreErr(nameUDPTarget, targetNew)
		conns.Delete(connKey)
		return
	}
}

func (sf *Server) reachUDPMaxPeers(conns *sync.Map) bool {
	if sf.udpMaxPeers <= 0 {
		return false
	}
	cur := 0
	conns.Range(func(_, _ any) bool { cur++; return true })
	return cur >= sf.udpMaxPeers
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

func (sf *Server) pipeUDPFromTarget(bindLn *net.UDPConn, conns *sync.Map, connKey string, target net.Conn, header []byte, srcAddr *net.UDPAddr) {
	rbuf, rput := sf.borrowBuf()
	defer func() {
		sf.closeIgnoreErr(nameUDPTarget, target)
		conns.Delete(connKey)
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
		if v, ok := conns.Load(connKey); ok {
			if p0, ok2 := v.(*udpPeer); ok2 {
				atomic.StoreInt64(&p0.lastSeen, time.Now().UnixNano())
			}
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
