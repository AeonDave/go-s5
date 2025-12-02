package server

import (
	"net"
	"testing"

	"github.com/AeonDave/go-s5/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestSelectUDPDial_FQDN_FallbackOrder(t *testing.T) {
	srv := &Server{}
	pkt := protocol.Datagram{DstAddr: protocol.AddrSpec{FQDN: "example.test", Port: 5353, AddrType: protocol.ATYPDomain}}

	t.Run("ipv4_client_prefers_ipv4_first", func(t *testing.T) {
		src := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10001}
		nets, addr := srv.selectUDPDial(src, &pkt)
		require.Equal(t, []string{"udp4", "udp6"}, nets)
		require.Equal(t, "example.test:5353", addr)
	})

	t.Run("ipv6_client_prefers_ipv6_first", func(t *testing.T) {
		src := &net.UDPAddr{IP: net.ParseIP("::1"), Port: 10002}
		nets, addr := srv.selectUDPDial(src, &pkt)
		require.Equal(t, []string{"udp6", "udp4"}, nets)
		require.Equal(t, "example.test:5353", addr)
	})
}
