package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"

	"github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/internal/protocol"
)

type closeWriter interface {
	CloseWrite() error
}

type closeReader interface {
	CloseRead() error
}

func (sf *Server) closeIgnoreErr(name string, c interface{}) {
	if c == nil {
		return
	}
	if cl, ok := c.(interface{ Close() error }); ok {
		if err := cl.Close(); err != nil {
			if !errors.Is(err, net.ErrClosed) && !strings.Contains(strings.ToLower(err.Error()), "use of closed network connection") {
				sf.logger.Errorf("close %s failed, %v", name, err)
			}
		}
	}
}

func isBenignNetClose(err error) bool {
	if err == nil {
		return true
	}
	msg := strings.ToLower(err.Error())
	return errors.Is(err, net.ErrClosed) || strings.Contains(msg, "use of closed network connection")
}

func isEOFOrClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

func isSafeReadFrom(r io.Reader) bool {
	if r == nil {
		return false
	}
	switch r.(type) {
	case *bytes.Reader, *strings.Reader:
		return true
	default:
		return false
	}
}

// borrowBuf gets a buffer from the pool and returns it with a put func.
func (sf *Server) borrowBuf() ([]byte, func()) {
	b := sf.bufferPool.Get()
	return b, func() { sf.bufferPool.Put(b) }
}

// Proxy copies data from src to dst.
// It prefers optimized io.Copy paths (ReaderFrom/WriterTo) and uses the
// shared buffer pool for the generic copy case to avoid per-call allocations.
func (sf *Server) Proxy(dst io.Writer, src io.Reader) error {
	rf, hasRF := dst.(io.ReaderFrom)
	wt, hasWT := src.(io.WriterTo)

	finish := func(err error) error {
		if cw, ok := dst.(closeWriter); ok {
			if cErr := cw.CloseWrite(); cErr != nil && !isBenignNetClose(cErr) {
				sf.logger.Errorf("close write failed, %v", cErr)
			}
		}
		if cr, ok := src.(closeReader); ok {
			_ = cr.CloseRead()
		}
		return err
	}

	switch {
	case hasRF && hasWT:
		// Prefer WriteTo in general to avoid problematic Readers that never EOF,
		// but use ReadFrom for *bytes.Reader to satisfy expected fast-path.
		if isSafeReadFrom(src) {
			_, err := rf.ReadFrom(src)
			return finish(err)
		}
		_, err := wt.WriteTo(dst)
		return finish(err)
	case hasRF:
		_, err := rf.ReadFrom(src)
		return finish(err)
	case hasWT:
		_, err := wt.WriteTo(dst)
		return finish(err)
	default:
		buf, put := sf.borrowBuf()
		defer put()
		_, err := io.CopyBuffer(dst, src, buf[:cap(buf)])
		return finish(err)
	}
}

// proxyDuplex proxies bidirectionally between (aSrc->aDst) and (bSrc->bDst),
// returning the first non-nil error.
func (sf *Server) proxyDuplex(aDst io.Writer, aSrc io.Reader, bDst io.Writer, bSrc io.Reader) error {
	errCh := make(chan error, 2)
	sf.goFunc(func() { errCh <- sf.Proxy(aDst, aSrc) })
	sf.goFunc(func() { errCh <- sf.Proxy(bDst, bSrc) })
	err1 := <-errCh
	err2 := <-errCh

	if err1 != nil && !isEOFOrClosed(err1) {
		return err1
	}
	if err2 != nil && !isEOFOrClosed(err2) {
		return err2
	}

	if err1 != nil {
		return err1
	}
	return err2
}

func SendReply(w io.Writer, rep uint8, bindAddr net.Addr) error {
	rsp := protocol.Reply{
		Version:  protocol.VersionSocks5,
		Response: rep,
		BndAddr:  protocol.AddrSpec{AddrType: protocol.ATYPIPv4, IP: net.IPv4zero, Port: 0},
	}

	if rsp.Response == protocol.RepSuccess {
		if tcpAddr, ok := bindAddr.(*net.TCPAddr); ok && tcpAddr != nil {
			rsp.BndAddr.IP = tcpAddr.IP
			rsp.BndAddr.Port = tcpAddr.Port
		} else if udpAddr, ok := bindAddr.(*net.UDPAddr); ok && udpAddr != nil {
			rsp.BndAddr.IP = udpAddr.IP
			rsp.BndAddr.Port = udpAddr.Port
		} else {
			rsp.Response = protocol.RepAddrTypeNotSupported
		}

		if rsp.BndAddr.IP.To4() != nil {
			rsp.BndAddr.AddrType = protocol.ATYPIPv4
		} else if rsp.BndAddr.IP.To16() != nil {
			rsp.BndAddr.AddrType = protocol.ATYPIPv6
		}
	}

	_, err := w.Write(rsp.Bytes())
	return err
}

func addrMatch(expect *protocol.AddrSpec, ip net.IP, port int, ipOnly bool) bool {
	if expect == nil {
		return true
	}
	ipOK := expect.IP == nil || expect.IP.IsUnspecified() || expect.IP.Equal(ip)
	if ipOnly {
		return ipOK
	}
	portOK := expect.Port == 0 || expect.Port == port
	return ipOK && portOK
}

func (sf *Server) dialOut(ctx context.Context, network, addr string, req *handler.Request) (net.Conn, error) {
	if sf.dialWithRequest != nil {
		return sf.dialWithRequest(ctx, network, addr, req)
	}
	if sf.dial != nil {
		return sf.dial(ctx, network, addr)
	}
	if sf.dialer != nil {
		return sf.dialer.DialContext(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func mapConnectDialError(err error) uint8 {
	if err == nil {
		return protocol.RepSuccess
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return protocol.RepTTLExpired
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return protocol.RepTTLExpired
		}
		if netErr.Temporary() {
			return protocol.RepNetworkUnreachable
		}
	}

	if errno := errnoFromError(err); errno != 0 {
		switch errno {
		case syscall.ECONNREFUSED:
			return protocol.RepConnectionRefused
		case syscall.ENETUNREACH, syscall.ENETDOWN, syscall.ENETRESET, syscall.EADDRNOTAVAIL:
			return protocol.RepNetworkUnreachable
		case syscall.EHOSTUNREACH, syscall.EHOSTDOWN:
			return protocol.RepHostUnreachable
		case syscall.ETIMEDOUT, syscall.EWOULDBLOCK:
			return protocol.RepTTLExpired
		}
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return protocol.RepHostUnreachable
		case dnsErr.Timeout():
			return protocol.RepTTLExpired
		}
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "refused"):
		return protocol.RepConnectionRefused
	case strings.Contains(msg, "network is unreachable") || strings.Contains(msg, "no route to host") || strings.Contains(msg, "unreachable"):
		return protocol.RepNetworkUnreachable
	case strings.Contains(msg, "i/o timeout") || strings.Contains(msg, "timed out"):
		return protocol.RepTTLExpired
	default:
		return protocol.RepHostUnreachable
	}
}

func errnoFromError(err error) syscall.Errno {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno
	}
	return 0
}
