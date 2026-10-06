package stack

const (
	CNTunnelIP   = "10.100.0.2"
	HKTunnelIP   = "10.100.0.3"
	TunnelCIDR   = "10.100.0.0/24"
	TunnelIf     = "wg0"
	UnboundPort  = 5335
	LocalUnbound = "127.0.0.1:5335"
	HKUnbound    = HKTunnelIP + ":5335"
)
