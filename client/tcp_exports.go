package client

import ctcp "github.com/AeonDave/go-s5/client/tcp"

// TCPStream exposes the helper for stream operations over CONNECT tunnels.
type TCPStream = ctcp.Stream

// NewTCPStream wraps a raw net.Conn into a TCPStream helper.
var NewTCPStream = ctcp.NewStream
