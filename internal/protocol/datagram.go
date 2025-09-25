package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
)

const errDatagramTooShortMsg = "datagram too short"

type Datagram struct {
	RSV     uint16
	Frag    byte
	DstAddr AddrSpec
	Data    []byte
}

func NewDatagram(destAddr string, data []byte) (Datagram, error) {
	dstAddr, err := ParseAddrSpec(destAddr)
	if err != nil {
		return Datagram{}, err
	}
	if dstAddr.AddrType == ATYPDomain && len(dstAddr.FQDN) > math.MaxUint8 {
		return Datagram{}, errors.New("destination host name too long")
	}
	return Datagram{RSV: 0, Frag: 0, DstAddr: dstAddr, Data: data}, nil
}

func ParseDatagram(b []byte) (Datagram, error) {
	if len(b) < 4+net.IPv4len+2 {
		return Datagram{}, errors.New(errDatagramTooShortMsg)
	}

	da := Datagram{RSV: 0, Frag: b[2], DstAddr: AddrSpec{AddrType: b[3]}}
	headLen := 4

	switch da.DstAddr.AddrType {
	case ATYPIPv4:
		if len(b) < headLen+net.IPv4len+2 {
			return Datagram{}, errors.New(errDatagramTooShortMsg)
		}
		da.DstAddr.IP = net.IPv4(b[4], b[5], b[6], b[7])
		da.DstAddr.Port = int(binary.BigEndian.Uint16(b[8:10]))
		headLen += net.IPv4len + 2
	case ATYPIPv6:
		if len(b) < headLen+net.IPv6len+2 {
			return Datagram{}, errors.New(errDatagramTooShortMsg)
		}
		da.DstAddr.IP = b[4 : 4+net.IPv6len]
		da.DstAddr.Port = int(binary.BigEndian.Uint16(b[20:22]))
		headLen += net.IPv6len + 2
	case ATYPDomain:
		addrLen := int(b[4])
		if len(b) < headLen+1+addrLen+2 {
			return Datagram{}, errors.New(errDatagramTooShortMsg)
		}
		da.DstAddr.FQDN = string(b[5 : 5+addrLen])
		da.DstAddr.Port = int(binary.BigEndian.Uint16(b[5+addrLen : 7+addrLen]))
		headLen += 1 + addrLen + 2
	default:
		return Datagram{}, ErrUnrecognizedAddrType
	}

	da.Data = b[headLen:]
	return da, nil
}

func (sf *Datagram) Header() []byte {
	return sf.buildBytes(false)
}

func (sf *Datagram) Bytes() []byte {
	return sf.buildBytes(true)
}

func (sf *Datagram) buildBytes(includeData bool) []byte {
	var addr []byte
	length := 6

	switch sf.DstAddr.AddrType {
	case ATYPIPv4:
		length += net.IPv4len
		addr = sf.DstAddr.IP.To4()
	case ATYPIPv6:
		length += net.IPv6len
		addr = sf.DstAddr.IP.To16()
	case ATYPDomain:
		length += 1 + len(sf.DstAddr.FQDN)
		addr = []byte(sf.DstAddr.FQDN)
	default:
		panic(fmt.Sprintf("invalid address type: %d", sf.DstAddr.AddrType))
	}

	bs := make([]byte, 0, length+len(sf.Data))
	bs = append(bs, byte(sf.RSV>>8), byte(sf.RSV), sf.Frag, sf.DstAddr.AddrType)
	if sf.DstAddr.AddrType == ATYPDomain {
		bs = append(bs, byte(len(sf.DstAddr.FQDN)))
	}
	bs = append(bs, addr...)
	bs = append(bs, byte(sf.DstAddr.Port>>8), byte(sf.DstAddr.Port))
	if includeData {
		bs = append(bs, sf.Data...)
	}
	return bs
}
