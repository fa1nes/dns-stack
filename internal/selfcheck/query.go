package selfcheck

import (
	"context"
	"math/rand"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/dnswire"
)

func queryWithSubnet(ctx context.Context, server, name, subnet string) ([]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return nil, err
	}
	packet, err := dnswire.BuildQueryWithSubnet(uint16(rand.Uint32()), name, dnswire.TypeA, prefix)
	if err != nil {
		return nil, err
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(6 * time.Second)
	if due, ok := ctx.Deadline(); ok && due.Before(deadline) {
		deadline = due
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	msg, err := dnswire.Unpack(buf[:n])
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, rr := range msg.Answers {
		if addr, ok := rr.A(); ok {
			out = append(out, addr)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
	return out, nil
}

func joinAddrs(addrs []netip.Addr, sep string) string {
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, sep)
}
