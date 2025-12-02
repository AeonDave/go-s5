package protocol

import (
	"fmt"
	"net"
	"strconv"
)

type AddrSpec struct {
	FQDN     string
	IP       net.IP
	Port     int
	AddrType byte
}

func (sf AddrSpec) String() string {
	if len(sf.IP) > 0 {
		return net.JoinHostPort(sf.IP.String(), strconv.Itoa(sf.Port))
	}
	return net.JoinHostPort(sf.FQDN, strconv.Itoa(sf.Port))
}

func (sf AddrSpec) Address() string {
	if sf.FQDN != "" {
		return fmt.Sprintf("%s (%s):%d", sf.FQDN, sf.IP, sf.Port)
	}
	return fmt.Sprintf("%s:%d", sf.IP, sf.Port)
}

func ParseAddrSpec(addr string) (AddrSpec, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return AddrSpec{}, err
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		return AddrSpec{}, err
	}

	ip := net.ParseIP(host)
	switch {
	case ip.To4() != nil:
		return AddrSpec{IP: ip, Port: portNum, AddrType: ATYPIPv4}, nil
	case ip.To16() != nil:
		return AddrSpec{IP: ip, Port: portNum, AddrType: ATYPIPv6}, nil
	default:
		return AddrSpec{FQDN: host, Port: portNum, AddrType: ATYPDomain}, nil
	}
}

func AddrTypeFromIP(ip net.IP) byte {
	if ip == nil {
		return ATYPIPv4
	}
	if ip.To4() != nil {
		return ATYPIPv4
	}
	return ATYPIPv6
}
