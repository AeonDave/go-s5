package client

import ctcp "github.com/AeonDave/go-s5/client/tcp"

// TCPStream exposes the helper for stream operations over CONNECT tunnels.
type TCPStream = ctcp.Stream

// NewTCPStream wraps a raw net.Conn into a TCPStream helper.
var NewTCPStream = ctcp.NewStream

// TCPStreamOption configures helper construction.
type TCPStreamOption = ctcp.Option

// WithTCPStreamLogger installs a logger on the TCP helper.
var WithTCPStreamLogger = ctcp.WithLogger

// WithTCPStreamRelayBufferSize overrides the relay copy buffer size.
var WithTCPStreamRelayBufferSize = ctcp.WithRelayBufferSize

// WithTCPStreamRelayActivityTimeout customizes the activity timeout used during relays.
var WithTCPStreamRelayActivityTimeout = ctcp.WithRelayActivityTimeout
