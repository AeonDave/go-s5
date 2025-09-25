package socks5

import (
	"bytes"
	"go-s5/internal/protocol"
	"io"
	"net"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddrSpecAddr(t *testing.T) {
	addr1 := protocol.AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	assert.Equal(t, "127.0.0.1:8080", addr1.String())
	assert.Equal(t, "127.0.0.1:8080", addr1.Address())

	addr2 := protocol.AddrSpec{FQDN: "localhost", IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	assert.Equal(t, "127.0.0.1:8080", addr2.String())
	assert.Equal(t, "localhost (127.0.0.1):8080", addr2.Address())

	addr3 := protocol.AddrSpec{FQDN: "localhost", Port: 8080}
	assert.Equal(t, "localhost:8080", addr3.String())
}

func TestParseAddrSpec(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantA   protocol.AddrSpec
		wantErr bool
	}{
		{"IPv4", "127.0.0.1:8080", protocol.AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 8080, AddrType: protocol.ATYPIPv4}, false},
		{"IPv6", "[::1]:8080", protocol.AddrSpec{IP: net.IPv6loopback, Port: 8080, AddrType: protocol.ATYPIPv6}, false},
		{"FQDN", "localhost:8080", protocol.AddrSpec{FQDN: "localhost", Port: 8080, AddrType: protocol.ATYPDomain}, false},
		{"invalid address,miss port", "localhost", protocol.AddrSpec{}, true},
		{"invalid port", "localhost:abc", protocol.AddrSpec{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotA, err := protocol.ParseAddrSpec(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAddrSpec() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotA, tt.wantA) {
				t.Errorf("ParseAddrSpec() gotA = %v, want %v", gotA, tt.wantA)
			}
		})
	}
}

func TestUserPassRequest(t *testing.T) {
	want := []byte{protocol.UserPassAuthVersion, 4, 'u', 's', 'e', 'r', 8, 'p', 'a', 's', 's', 'w', 'o', 'r', 'd'}
	userpass := protocol.NewUserPassRequest(protocol.UserPassAuthVersion, []byte("user"), []byte("password"))
	assert.Equal(t, want, userpass.Bytes())

	upr, err := protocol.ParseUserPassRequest(bytes.NewReader(want))
	require.NoError(t, err)
	assert.Equal(t, userpass, upr)
}

func TestUserPassReply(t *testing.T) {
	reader := bytes.NewReader([]byte{protocol.UserPassAuthVersion, protocol.AuthSuccess})
	upr, err := protocol.ParseUserPassReply(reader)
	require.NoError(t, err)
	assert.Equal(t, protocol.UserPassReply{protocol.UserPassAuthVersion, protocol.AuthSuccess}, upr)
}

func TestDatagram(t *testing.T) {
	if _, err := protocol.NewDatagram("localhost", nil); err == nil {
		t.Fatalf("expected error for missing port")
	}

	longHost := "localhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhost" +
		"localhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhost" +
		"localhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhostlocalhost"
	if _, err := protocol.NewDatagram(longHost+":8080", nil); err == nil {
		t.Fatalf("expected error for long host")
	}

	dg, err := protocol.NewDatagram("localhost:8080", []byte{1, 2, 3})
	require.NoError(t, err)
	require.Equal(t, protocol.Datagram{0, 0, protocol.AddrSpec{FQDN: "localhost", Port: 8080, AddrType: protocol.ATYPDomain}, []byte{1, 2, 3}}, dg)
	require.Equal(t, []byte{0, 0, 0, protocol.ATYPDomain, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x1f, 0x90}, dg.Header())
	require.Equal(t, []byte{0, 0, 0, protocol.ATYPDomain, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x1f, 0x90, 1, 2, 3}, dg.Bytes())

	dg, err = protocol.NewDatagram("127.0.0.1:8080", []byte{1, 2, 3})
	require.NoError(t, err)
	require.Equal(t, protocol.Datagram{0, 0, protocol.AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 8080, AddrType: protocol.ATYPIPv4}, []byte{1, 2, 3}}, dg)
	require.Equal(t, []byte{0, 0, 0, protocol.ATYPIPv4, 127, 0, 0, 1, 0x1f, 0x90}, dg.Header())
	require.Equal(t, []byte{0, 0, 0, protocol.ATYPIPv4, 127, 0, 0, 1, 0x1f, 0x90, 1, 2, 3}, dg.Bytes())

	dg, err = protocol.NewDatagram("[::1]:8080", []byte{1, 2, 3})
	require.NoError(t, err)
	require.Equal(t, protocol.Datagram{0, 0, protocol.AddrSpec{IP: net.IPv6loopback, Port: 8080, AddrType: protocol.ATYPIPv6}, []byte{1, 2, 3}}, dg)
	require.Equal(t, []byte{0, 0, 0, protocol.ATYPIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1f, 0x90}, dg.Header())
	require.Equal(t, []byte{0, 0, 0, protocol.ATYPIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1f, 0x90, 1, 2, 3}, dg.Bytes())
}

func TestParseDatagram(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantDa  protocol.Datagram
		wantErr bool
	}{
		{"IPv4", []byte{0, 0, 0, protocol.ATYPIPv4, 127, 0, 0, 1, 0x1f, 0x90, 1, 2, 3}, protocol.Datagram{0, 0, protocol.AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 8080, AddrType: protocol.ATYPIPv4}, []byte{1, 2, 3}}, false},
		{"IPv6", []byte{0, 0, 0, protocol.ATYPIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1f, 0x90, 1, 2, 3}, protocol.Datagram{0, 0, protocol.AddrSpec{IP: net.IPv6loopback, Port: 8080, AddrType: protocol.ATYPIPv6}, []byte{1, 2, 3}}, false},
		{"FQDN", []byte{0, 0, 0, protocol.ATYPDomain, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x1f, 0x90, 1, 2, 3}, protocol.Datagram{0, 0, protocol.AddrSpec{FQDN: "localhost", Port: 8080, AddrType: protocol.ATYPDomain}, []byte{1, 2, 3}}, false},
		{"invalid address type", []byte{0, 0, 0, 0x02, 127, 0, 0, 1, 0x1f, 0x90}, protocol.Datagram{}, true},
		{"less min length", []byte{0, 0, 0, protocol.ATYPIPv4, 127, 0, 0, 1, 0x1f}, protocol.Datagram{}, true},
		{"less domain length", []byte{0, 0, 0, protocol.ATYPDomain, 10, 127, 0, 0, 1, 0x1f, 0x09}, protocol.Datagram{}, true},
		{"less ipv6 length", []byte{0, 0, 0, protocol.ATYPIPv6, 127, 0, 0, 1, 0x1f, 0x09}, protocol.Datagram{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDa, err := protocol.ParseDatagram(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDatagram() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && !reflect.DeepEqual(gotDa, tt.wantDa) {
				t.Errorf("ParseDatagram() gotDa = %v, want %v", gotDa, tt.wantDa)
			}
		})
	}
}

func TestParseRequest(t *testing.T) {
	tests := []struct {
		name    string
		reader  io.Reader
		want    protocol.Request
		wantErr bool
	}{
		{"SOCKS5 IPV4", bytes.NewReader([]byte{protocol.VersionSocks5, protocol.CommandConnect, 0, protocol.ATYPIPv4, 127, 0, 0, 1, 0x1f, 0x90}), protocol.Request{protocol.VersionSocks5, protocol.CommandConnect, 0, protocol.AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 8080, AddrType: protocol.ATYPIPv4}}, false},
		{"SOCKS5 IPV6", bytes.NewReader([]byte{protocol.VersionSocks5, protocol.CommandConnect, 0, protocol.ATYPIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1f, 0x90}), protocol.Request{protocol.VersionSocks5, protocol.CommandConnect, 0, protocol.AddrSpec{IP: net.IPv6zero, Port: 8080, AddrType: protocol.ATYPIPv6}}, false},
		{"SOCKS5 FQDN", bytes.NewReader([]byte{protocol.VersionSocks5, protocol.CommandConnect, 0, protocol.ATYPDomain, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x1f, 0x90}), protocol.Request{protocol.VersionSocks5, protocol.CommandConnect, 0, protocol.AddrSpec{FQDN: "localhost", Port: 8080, AddrType: protocol.ATYPDomain}}, false},
		{"SOCKS5 invalid address type", bytes.NewReader([]byte{protocol.VersionSocks5, protocol.CommandConnect, 0, 0x02, 0, 0, 0, 0, 0, 0}), protocol.Request{Version: protocol.VersionSocks5, Command: protocol.CommandConnect, DstAddr: protocol.AddrSpec{AddrType: 0x02}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHd, err := protocol.ParseRequest(tt.reader)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotHd, tt.want) {
				t.Errorf("ParseRequest() gotHd = %+v, want %+v", gotHd, tt.want)
			}
		})
	}
}

func TestRequest_Bytes(t *testing.T) {
	tests := []struct {
		name    string
		request protocol.Request
		wantB   []byte
	}{
		{"SOCKS5 IPV4", protocol.Request{protocol.VersionSocks5, protocol.CommandConnect, 0, protocol.AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 8080, AddrType: protocol.ATYPIPv4}}, []byte{protocol.VersionSocks5, protocol.CommandConnect, 0, protocol.ATYPIPv4, 127, 0, 0, 1, 0x1f, 0x90}},
		{"SOCKS5 IPV6", protocol.Request{protocol.VersionSocks5, protocol.CommandConnect, 0, protocol.AddrSpec{IP: net.IPv6zero, Port: 8080, AddrType: protocol.ATYPIPv6}}, []byte{protocol.VersionSocks5, protocol.CommandConnect, 0, protocol.ATYPIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1f, 0x90}},
		{"SOCKS5 FQDN", protocol.Request{protocol.VersionSocks5, protocol.CommandConnect, 0, protocol.AddrSpec{FQDN: "localhost", Port: 8080, AddrType: protocol.ATYPDomain}}, []byte{protocol.VersionSocks5, protocol.CommandConnect, 0, protocol.ATYPDomain, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x1f, 0x90}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotB := tt.request.Bytes(); !reflect.DeepEqual(gotB, tt.wantB) {
				t.Errorf("Bytes() = %v, want %v", gotB, tt.wantB)
			}
		})
	}
}

func TestParseReply(t *testing.T) {
	tests := []struct {
		name    string
		reader  io.Reader
		want    protocol.Reply
		wantErr bool
	}{
		{"SOCKS5 IPV4", bytes.NewReader([]byte{protocol.VersionSocks5, protocol.RepSuccess, 0, protocol.ATYPIPv4, 127, 0, 0, 1, 0x1f, 0x90}), protocol.Reply{protocol.VersionSocks5, protocol.RepSuccess, 0, protocol.AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 8080, AddrType: protocol.ATYPIPv4}}, false},
		{"SOCKS5 IPV6", bytes.NewReader([]byte{protocol.VersionSocks5, protocol.RepSuccess, 0, protocol.ATYPIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1f, 0x90}), protocol.Reply{protocol.VersionSocks5, protocol.RepSuccess, 0, protocol.AddrSpec{IP: net.IPv6zero, Port: 8080, AddrType: protocol.ATYPIPv6}}, false},
		{"SOCKS5 FQDN", bytes.NewReader([]byte{protocol.VersionSocks5, protocol.RepSuccess, 0, protocol.ATYPDomain, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x1f, 0x90}), protocol.Reply{protocol.VersionSocks5, protocol.RepSuccess, 0, protocol.AddrSpec{FQDN: "localhost", Port: 8080, AddrType: protocol.ATYPDomain}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := protocol.ParseReply(tt.reader)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseReply() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseReply() got = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestReply_Bytes(t *testing.T) {
	tests := []struct {
		name  string
		reply protocol.Reply
		wantB []byte
	}{
		{"SOCKS5 IPV4", protocol.Reply{protocol.VersionSocks5, protocol.CommandConnect, 0, protocol.AddrSpec{IP: net.IPv4(127, 0, 0, 1), Port: 8080, AddrType: protocol.ATYPIPv4}}, []byte{protocol.VersionSocks5, protocol.CommandConnect, 0, protocol.ATYPIPv4, 127, 0, 0, 1, 0x1f, 0x90}},
		{"SOCKS5 IPV6", protocol.Reply{protocol.VersionSocks5, protocol.CommandConnect, 0, protocol.AddrSpec{IP: net.IPv6zero, Port: 8080, AddrType: protocol.ATYPIPv6}}, []byte{protocol.VersionSocks5, protocol.CommandConnect, 0, protocol.ATYPIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1f, 0x90}},
		{"SOCKS5 FQDN", protocol.Reply{protocol.VersionSocks5, protocol.CommandConnect, 0, protocol.AddrSpec{FQDN: "localhost", Port: 8080, AddrType: protocol.ATYPDomain}}, []byte{protocol.VersionSocks5, protocol.CommandConnect, 0, protocol.ATYPDomain, 9, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x1f, 0x90}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotB := tt.reply.Bytes(); !reflect.DeepEqual(gotB, tt.wantB) {
				t.Errorf("Bytes() = %v, want %v", gotB, tt.wantB)
			}
		})
	}
}

func TestMethodRequest(t *testing.T) {
	mr := protocol.NewMethodRequest(protocol.VersionSocks5, []byte{protocol.MethodNoAuth, protocol.MethodUserPassAuth})
	want := []byte{protocol.VersionSocks5, 2, protocol.MethodNoAuth, protocol.MethodUserPassAuth}
	assert.Equal(t, want, mr.Bytes())

	mr1, err := protocol.ParseMethodRequest(bytes.NewReader(want))
	require.NoError(t, err)
	assert.Equal(t, mr, mr1)
}

func TestMethodReply(t *testing.T) {
	mr, err := protocol.ParseMethodReply(bytes.NewReader([]byte{protocol.VersionSocks5, protocol.RepSuccess}))
	require.NoError(t, err)
	assert.Equal(t, protocol.MethodReply{protocol.VersionSocks5, protocol.RepSuccess}, mr)
}
