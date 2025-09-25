package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type Request struct {
	Version  byte
	Command  byte
	Reserved byte
	DstAddr  AddrSpec
}

func ParseRequest(r io.Reader) (req Request, err error) {
	tmp := make([]byte, 2)
	if _, err = io.ReadFull(r, tmp); err != nil {
		return req, fmt.Errorf("error reading version and command: %v", err)
	}
	req.Version, req.Command = tmp[0], tmp[1]
	if req.Version != VersionSocks5 {
		return req, fmt.Errorf("unrecognized SOCKS version: %d", req.Version)
	}

	if _, err = io.ReadFull(r, tmp); err != nil {
		return req, fmt.Errorf("error reading RSV and address type: %v", err)
	}
	req.Reserved, req.DstAddr.AddrType = tmp[0], tmp[1]

	// Validate address type early
	if req.DstAddr.AddrType != ATYPIPv4 && req.DstAddr.AddrType != ATYPIPv6 && req.DstAddr.AddrType != ATYPDomain {
		return req, ErrUnrecognizedAddrType
	}

	addrLen := map[byte]int{ATYPIPv4: net.IPv4len, ATYPIPv6: net.IPv6len}[req.DstAddr.AddrType]
	if req.DstAddr.AddrType == ATYPDomain {
		if _, err = io.ReadFull(r, tmp[:1]); err != nil {
			return req, fmt.Errorf("error reading domain length: %v", err)
		}
		addrLen = int(tmp[0])
	}
	addr := make([]byte, addrLen+2)
	if _, err = io.ReadFull(r, addr); err != nil {
		return req, fmt.Errorf("error reading address: %v", err)
	}

	switch req.DstAddr.AddrType {
	case ATYPIPv4:
		req.DstAddr.IP = net.IPv4(addr[0], addr[1], addr[2], addr[3])
	case ATYPIPv6:
		req.DstAddr.IP = addr[:net.IPv6len]
	case ATYPDomain:
		req.DstAddr.FQDN = string(addr[:addrLen])
	}
	req.DstAddr.Port = int(binary.BigEndian.Uint16(addr[addrLen:]))
	return req, nil
}

func (h Request) Bytes() []byte {
	var addr []byte
	switch h.DstAddr.AddrType {
	case ATYPDomain:
		addr = []byte(h.DstAddr.FQDN)
	case ATYPIPv4:
		if ip4 := h.DstAddr.IP.To4(); ip4 != nil {
			addr = ip4
		} else {
			addr = h.DstAddr.IP
		}
	case ATYPIPv6:
		if ip16 := h.DstAddr.IP.To16(); ip16 != nil {
			addr = ip16
		} else {
			addr = h.DstAddr.IP
		}
	default:
		addr = h.DstAddr.IP
	}
	b := make([]byte, 0, 6+len(addr))
	b = append(b, h.Version, h.Command, h.Reserved, h.DstAddr.AddrType)
	if h.DstAddr.AddrType == ATYPDomain {
		b = append(b, byte(len(h.DstAddr.FQDN)))
	}
	b = append(b, addr...)
	b = append(b, byte(h.DstAddr.Port>>8), byte(h.DstAddr.Port))
	return b
}

type Reply struct {
	Version  byte
	Response byte
	Reserved byte
	BndAddr  AddrSpec
}

func ParseReply(r io.Reader) (rep Reply, err error) {
	tmp := make([]byte, 2)
	if _, err = io.ReadFull(r, tmp); err != nil {
		return rep, fmt.Errorf("error reading version and response: %v", err)
	}
	rep.Version, rep.Response = tmp[0], tmp[1]
	if rep.Version != VersionSocks5 {
		return rep, fmt.Errorf("unrecognized SOCKS version: %d", rep.Version)
	}

	if _, err = io.ReadFull(r, tmp); err != nil {
		return rep, fmt.Errorf("error reading RSV and address type: %v", err)
	}
	rep.Reserved, rep.BndAddr.AddrType = tmp[0], tmp[1]

	addrLen := map[byte]int{ATYPIPv4: net.IPv4len, ATYPIPv6: net.IPv6len}[rep.BndAddr.AddrType]
	if rep.BndAddr.AddrType == ATYPDomain {
		if _, err = io.ReadFull(r, tmp[:1]); err != nil {
			return rep, fmt.Errorf("error reading domain length: %v", err)
		}
		addrLen = int(tmp[0])
	}
	addr := make([]byte, addrLen+2)
	if _, err = io.ReadFull(r, addr); err != nil {
		return rep, fmt.Errorf("error reading address: %v", err)
	}

	switch rep.BndAddr.AddrType {
	case ATYPIPv4:
		rep.BndAddr.IP = net.IPv4(addr[0], addr[1], addr[2], addr[3])
	case ATYPIPv6:
		rep.BndAddr.IP = addr[:net.IPv6len]
	case ATYPDomain:
		rep.BndAddr.FQDN = string(addr[:addrLen])
	}
	rep.BndAddr.Port = int(binary.BigEndian.Uint16(addr[addrLen:]))
	return rep, nil
}

func (sf Reply) Bytes() []byte {
	var addr []byte
	switch sf.BndAddr.AddrType {
	case ATYPDomain:
		addr = []byte(sf.BndAddr.FQDN)
	case ATYPIPv4:
		if ip4 := sf.BndAddr.IP.To4(); ip4 != nil {
			addr = ip4
		} else {
			addr = sf.BndAddr.IP
		}
	case ATYPIPv6:
		if ip16 := sf.BndAddr.IP.To16(); ip16 != nil {
			addr = ip16
		} else {
			addr = sf.BndAddr.IP
		}
	default:
		addr = sf.BndAddr.IP
	}
	b := make([]byte, 0, 6+len(addr))
	b = append(b, sf.Version, sf.Response, sf.Reserved, sf.BndAddr.AddrType)
	if sf.BndAddr.AddrType == ATYPDomain {
		b = append(b, byte(len(sf.BndAddr.FQDN)))
	}
	b = append(b, addr...)
	b = append(b, byte(sf.BndAddr.Port>>8), byte(sf.BndAddr.Port))
	return b
}
