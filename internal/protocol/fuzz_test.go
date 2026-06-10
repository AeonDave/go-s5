package protocol

// Native Go fuzz targets for every wire-format parser. Each target asserts
// two properties on arbitrary input:
//
//  1. The parser never panics and never reads out of bounds.
//  2. Round-trip stability: anything the parser accepts re-encodes via
//     Bytes()/String() into a form the parser accepts again, yielding an
//     equivalent value.
//
// Run continuously with:
//
//	go test -fuzz=FuzzParseDatagram -fuzztime=30s ./internal/protocol/
//
// The committed corpus under testdata/fuzz is replayed on every plain
// `go test` run, so past findings act as regression tests.

import (
	"bytes"
	"testing"
)

func FuzzParseDatagram(f *testing.F) {
	f.Add([]byte{0, 0, 0, ATYPIPv4, 127, 0, 0, 1, 0, 80, 'h', 'i'})
	f.Add([]byte{0, 0, 0, ATYPIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187})
	f.Add([]byte{0, 0, 0, ATYPDomain, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 53, 'd', 'a', 't', 'a'})
	f.Add([]byte{0, 0, 0, ATYPDomain, 0, 0, 0})
	f.Add([]byte{0, 0, 1, ATYPIPv4, 1, 2, 3, 4, 255, 255})

	f.Fuzz(func(t *testing.T, data []byte) {
		dg, err := ParseDatagram(data)
		if err != nil {
			return
		}
		encoded := dg.Bytes()
		again, err := ParseDatagram(encoded)
		if err != nil {
			t.Fatalf("re-parse of encoded datagram failed: %v (input %x)", err, data)
		}
		if again.Frag != dg.Frag || again.DstAddr.AddrType != dg.DstAddr.AddrType ||
			again.DstAddr.Port != dg.DstAddr.Port || again.DstAddr.FQDN != dg.DstAddr.FQDN {
			t.Fatalf("round trip mismatch: got %+v want %+v", again, dg)
		}
		if !again.DstAddr.IP.Equal(dg.DstAddr.IP) {
			t.Fatalf("round trip IP mismatch: got %v want %v", again.DstAddr.IP, dg.DstAddr.IP)
		}
		if !bytes.Equal(again.Data, dg.Data) {
			t.Fatalf("round trip payload mismatch: got %x want %x", again.Data, dg.Data)
		}
		if got, want := len(encoded), dg.WireSize(); got != want {
			t.Fatalf("WireSize disagrees with Bytes: got %d want %d", want, got)
		}
		if appended := dg.AppendBytes(nil); !bytes.Equal(appended, encoded) {
			t.Fatalf("AppendBytes disagrees with Bytes: %x vs %x", appended, encoded)
		}
	})
}

func FuzzParseRequest(f *testing.F) {
	f.Add([]byte{VersionSocks5, CommandConnect, 0, ATYPIPv4, 127, 0, 0, 1, 0, 80})
	f.Add([]byte{VersionSocks5, CommandBind, 0, ATYPDomain, 4, 'h', 'o', 's', 't', 1, 187})
	f.Add([]byte{VersionSocks5, CommandAssociate, 0, ATYPIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 53})
	f.Add([]byte{4, 1, 0, 1, 1, 2, 3, 4, 0, 80}) // SOCKS4 must be rejected

	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := ParseRequest(bytes.NewReader(data))
		if err != nil {
			return
		}
		if req.Version != VersionSocks5 {
			t.Fatalf("parser accepted version %d", req.Version)
		}
		switch req.DstAddr.AddrType {
		case ATYPIPv4, ATYPIPv6, ATYPDomain:
		default:
			t.Fatalf("parser accepted address type %d", req.DstAddr.AddrType)
		}
		again, err := ParseRequest(bytes.NewReader(req.Bytes()))
		if err != nil {
			t.Fatalf("re-parse of encoded request failed: %v (input %x)", err, data)
		}
		if again.Command != req.Command || again.Reserved != req.Reserved ||
			again.DstAddr.AddrType != req.DstAddr.AddrType ||
			again.DstAddr.Port != req.DstAddr.Port || again.DstAddr.FQDN != req.DstAddr.FQDN {
			t.Fatalf("round trip mismatch: got %+v want %+v", again, req)
		}
		if !again.DstAddr.IP.Equal(req.DstAddr.IP) {
			t.Fatalf("round trip IP mismatch: got %v want %v", again.DstAddr.IP, req.DstAddr.IP)
		}
	})
}

func FuzzParseReply(f *testing.F) {
	f.Add([]byte{VersionSocks5, RepSuccess, 0, ATYPIPv4, 127, 0, 0, 1, 4, 56})
	f.Add([]byte{VersionSocks5, RepHostUnreachable, 0, ATYPDomain, 2, 'o', 'k', 0, 0})
	f.Add([]byte{VersionSocks5, RepSuccess, 0, 0xee, 0, 80}) // bogus ATYP must be rejected

	f.Fuzz(func(t *testing.T, data []byte) {
		rep, err := ParseReply(bytes.NewReader(data))
		if err != nil {
			return
		}
		if rep.Version != VersionSocks5 {
			t.Fatalf("parser accepted version %d", rep.Version)
		}
		switch rep.BndAddr.AddrType {
		case ATYPIPv4, ATYPIPv6, ATYPDomain:
		default:
			t.Fatalf("parser accepted address type %d", rep.BndAddr.AddrType)
		}
		again, err := ParseReply(bytes.NewReader(rep.Bytes()))
		if err != nil {
			t.Fatalf("re-parse of encoded reply failed: %v (input %x)", err, data)
		}
		if again.Response != rep.Response || again.Reserved != rep.Reserved ||
			again.BndAddr.AddrType != rep.BndAddr.AddrType ||
			again.BndAddr.Port != rep.BndAddr.Port || again.BndAddr.FQDN != rep.BndAddr.FQDN {
			t.Fatalf("round trip mismatch: got %+v want %+v", again, rep)
		}
		if !again.BndAddr.IP.Equal(rep.BndAddr.IP) {
			t.Fatalf("round trip IP mismatch: got %v want %v", again.BndAddr.IP, rep.BndAddr.IP)
		}
	})
}

func FuzzParseMethodRequest(f *testing.F) {
	f.Add([]byte{VersionSocks5, 1, MethodNoAuth})
	f.Add([]byte{VersionSocks5, 2, MethodNoAuth, MethodUserPassAuth})
	f.Add([]byte{VersionSocks5, 0})
	f.Add([]byte{VersionSocks5, 255})

	f.Fuzz(func(t *testing.T, data []byte) {
		mr, err := ParseMethodRequest(bytes.NewReader(data))
		if err != nil {
			return
		}
		if int(mr.NMethods) != len(mr.Methods) {
			t.Fatalf("NMethods %d disagrees with len(Methods) %d", mr.NMethods, len(mr.Methods))
		}
		again, err := ParseMethodRequest(bytes.NewReader(mr.Bytes()))
		if err != nil {
			t.Fatalf("re-parse of encoded method request failed: %v", err)
		}
		if again.Ver != mr.Ver || again.NMethods != mr.NMethods || !bytes.Equal(again.Methods, mr.Methods) {
			t.Fatalf("round trip mismatch: got %+v want %+v", again, mr)
		}
	})
}

func FuzzParseUserPassRequest(f *testing.F) {
	f.Add([]byte{UserPassAuthVersion, 5, 'a', 'l', 'i', 'c', 'e', 6, 's', 'e', 'c', 'r', 'e', 't'})
	f.Add([]byte{UserPassAuthVersion, 0, 0})
	f.Add([]byte{2, 1, 'x', 1, 'y'}) // wrong sub-negotiation version must be rejected

	f.Fuzz(func(t *testing.T, data []byte) {
		up, err := ParseUserPassRequest(bytes.NewReader(data))
		if err != nil {
			return
		}
		if up.Ver != UserPassAuthVersion {
			t.Fatalf("parser accepted auth version %d", up.Ver)
		}
		if int(up.Ulen) != len(up.User) || int(up.Plen) != len(up.Pass) {
			t.Fatalf("length fields disagree with payload: %+v", up)
		}
		again, err := ParseUserPassRequest(bytes.NewReader(up.Bytes()))
		if err != nil {
			t.Fatalf("re-parse of encoded user/pass request failed: %v", err)
		}
		if !bytes.Equal(again.User, up.User) || !bytes.Equal(again.Pass, up.Pass) {
			t.Fatalf("round trip mismatch: got %+v want %+v", again, up)
		}
	})
}

func FuzzParseAddrSpec(f *testing.F) {
	f.Add("127.0.0.1:80")
	f.Add("[::1]:443")
	f.Add("example.com:65535")
	f.Add("host:-1")
	f.Add("[fe80::1%eth0]:53")
	f.Add(":0")

	f.Fuzz(func(t *testing.T, addr string) {
		spec, err := ParseAddrSpec(addr)
		if err != nil {
			return
		}
		if spec.Port < 0 || spec.Port > 65535 {
			t.Fatalf("parser accepted out-of-range port %d", spec.Port)
		}
		again, err := ParseAddrSpec(spec.String())
		if err != nil {
			t.Fatalf("re-parse of %q (from %q) failed: %v", spec.String(), addr, err)
		}
		if again.Port != spec.Port || again.FQDN != spec.FQDN || again.AddrType != spec.AddrType {
			t.Fatalf("round trip mismatch: got %+v want %+v", again, spec)
		}
		if !again.IP.Equal(spec.IP) {
			t.Fatalf("round trip IP mismatch: got %v want %v", again.IP, spec.IP)
		}
	})
}
