package protocol

import (
	"fmt"
	"io"
	"math"
)

var (
	ErrUserAuthFailed  = fmt.Errorf("user authentication failed")
	ErrNoSupportedAuth = fmt.Errorf("no supported authentication mechanism")
)

type UserPassRequest struct {
	Ver  byte   // Version
	Ulen byte   // Username length
	Plen byte   // Password length
	User []byte // Username
	Pass []byte // Password
}

type UserPassReply struct {
	Ver    byte
	Status byte
}

func NewUserPassRequest(ver byte, user, pass []byte) (UserPassRequest, error) {
	if len(user) > math.MaxUint8 {
		return UserPassRequest{}, fmt.Errorf("username too long: %d", len(user))
	}
	if len(pass) > math.MaxUint8 {
		return UserPassRequest{}, fmt.Errorf("password too long: %d", len(pass))
	}
	return UserPassRequest{
		Ver:  ver,
		Ulen: byte(len(user)),
		Plen: byte(len(pass)),
		User: user,
		Pass: pass,
	}, nil
}

func ParseUserPassRequest(r io.Reader) (UserPassRequest, error) {
	tmp := make([]byte, 2)

	if _, err := io.ReadAtLeast(r, tmp, 2); err != nil {
		return UserPassRequest{}, err
	}
	ver, ulen := tmp[0], tmp[1]

	if ver != UserPassAuthVersion {
		return UserPassRequest{}, fmt.Errorf("unsupported auth version: %v", ver)
	}

	user := make([]byte, ulen)
	if _, err := io.ReadAtLeast(r, user, int(ulen)); err != nil {
		return UserPassRequest{}, err
	}

	if _, err := r.Read(tmp[:1]); err != nil {
		return UserPassRequest{}, err
	}
	pLen := tmp[0]

	pass := make([]byte, pLen)
	if _, err := io.ReadAtLeast(r, pass, int(pLen)); err != nil {
		return UserPassRequest{}, err
	}

	return UserPassRequest{Ver: ver, Ulen: ulen, Plen: pLen, User: user, Pass: pass}, nil
}

func (sf UserPassRequest) Bytes() []byte {
	b := append([]byte{sf.Ver, sf.Ulen}, sf.User...)
	b = append(b, sf.Plen)
	return append(b, sf.Pass...)
}

func ParseUserPassReply(r io.Reader) (UserPassReply, error) {
	data := make([]byte, 2)
	if _, err := io.ReadFull(r, data); err != nil {
		return UserPassReply{}, err
	}
	return UserPassReply{Ver: data[0], Status: data[1]}, nil
}
