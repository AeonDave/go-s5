package protocol

import (
	"io"
)

type MethodRequest struct {
	Ver      byte
	NMethods byte
	Methods  []byte
}

func NewMethodRequest(ver byte, methods []byte) MethodRequest {
	return MethodRequest{
		Ver:      ver,
		NMethods: byte(len(methods)),
		Methods:  methods,
	}
}

func ParseMethodRequest(r io.Reader) (mr MethodRequest, err error) {
	tmp := make([]byte, 2)
	if _, err = io.ReadFull(r, tmp); err != nil {
		return
	}
	mr.Ver, mr.NMethods = tmp[0], tmp[1]
	mr.Methods = make([]byte, mr.NMethods)
	_, err = io.ReadFull(r, mr.Methods)
	return
}

func (sf MethodRequest) Bytes() []byte {
	return append([]byte{sf.Ver, sf.NMethods}, sf.Methods...)
}

type MethodReply struct {
	Ver    byte
	Method byte
}

func ParseMethodReply(r io.Reader) (mr MethodReply, err error) {
	tmp := make([]byte, 2)
	if _, err = io.ReadFull(r, tmp); err != nil {
		return
	}
	mr.Ver, mr.Method = tmp[0], tmp[1]
	return
}
