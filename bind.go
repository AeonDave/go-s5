package s5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/AeonDave/go-s5/handler"
	"github.com/AeonDave/go-s5/internal/protocol"
)

func (sf *Server) handleBind(_ context.Context, writer io.Writer, request *handler.Request) error {
	ln, err := net.ListenTCP("tcp", sf.pickBindTCPAddr(request))
	if err != nil {
		if err := SendReply(writer, protocol.RepServerFailure, nil); err != nil {
			return fmt.Errorf("failed to send reply: %v", err)
		}
		return fmt.Errorf("listen tcp (bind) failed, %v", err)
	}

	if err := SendReply(writer, protocol.RepSuccess, ln.Addr()); err != nil {
		sf.closeIgnoreErr(nameBindListener, ln)
		return fmt.Errorf(fmtFailedSendReply, err)
	}

	peer, err := sf.acceptBindPeer(ln, writer, request)
	if err != nil || peer == nil {
		return err
	}

	if err := SendReply(writer, protocol.RepSuccess, peer.RemoteAddr()); err != nil {
		sf.closeIgnoreErr(nameBindListener, ln)
		sf.closeIgnoreErr("bind peer", peer)
		return fmt.Errorf(fmtFailedSendReply, err)
	}
	sf.closeIgnoreErr(nameBindListener, ln)
	return sf.proxyDuplex(peer, request.Reader, writer, peer)
}

func (sf *Server) pickBindTCPAddr(request *handler.Request) *net.TCPAddr {
	if sf.bindIP != nil {
		return &net.TCPAddr{IP: sf.bindIP, Port: 0}
	}
	if tcpLocal, ok := request.LocalAddr.(*net.TCPAddr); ok && tcpLocal != nil {
		return &net.TCPAddr{IP: tcpLocal.IP, Port: 0}
	}
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (sf *Server) acceptBindPeer(ln *net.TCPListener, writer io.Writer, request *handler.Request) (net.Conn, error) {
	for {
		if sf.bindAcceptTimeout > 0 {
			_ = ln.SetDeadline(time.Now().Add(sf.bindAcceptTimeout))
		}
		c, err := ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				_ = SendReply(writer, protocol.RepTTLExpired, ln.Addr())
			}
			sf.closeIgnoreErr(nameBindListener, ln)
			if isEOFOrClosed(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("bind accept failed, %v", err)
		}
		if !sf.isExpectedBindPeer(c, request) {
			sf.closeIgnoreErr("bind unexpected peer", c)
			continue
		}
		return c, nil
	}
}

func (sf *Server) isExpectedBindPeer(c net.Conn, request *handler.Request) bool {
	ra, okRA := c.RemoteAddr().(*net.TCPAddr)
	if !okRA {
		return true
	}
	return addrMatch(request.DestAddr, ra.IP, ra.Port, sf.bindPeerCheckIPOnly)
}
