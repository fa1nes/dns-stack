package resolve

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/dnswire"
)

const (
	DefaultTimeout = 15 * time.Second
	maxUDPResponse = 4096
)

type Status int

const (
	StatusOK Status = iota
	StatusNXDomain
	StatusServFail
	StatusTimeout
)

type Answer struct {
	Status Status
	Msg    *dnswire.Msg
	Raw    []byte
}

type Client struct {
	Server  netip.AddrPort
	Timeout time.Duration
}

func NewClient(host string, port int, timeout time.Duration) (*Client, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return nil, err
	}
	if port <= 0 || port > 65535 {
		return nil, errors.New("解析器端口必须在 1..65535 之间")
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{Server: netip.AddrPortFrom(addr, uint16(port)), Timeout: timeout}, nil
}

func randomID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint16(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint16(b[:])
}

func (c *Client) Query(ctx context.Context, name string, qtype uint16) Answer {
	return c.QueryWithSubnet(ctx, name, qtype, netip.Prefix{})
}

func (c *Client) QueryWithSubnet(ctx context.Context, name string, qtype uint16, subnet netip.Prefix) Answer {
	id := randomID()
	var (
		packet []byte
		err    error
	)
	if subnet.IsValid() {
		packet, err = dnswire.BuildQueryWithSubnet(id, name, qtype, subnet)
	} else {
		packet, err = dnswire.BuildQuery(id, name, qtype)
	}
	if err != nil {
		return Answer{Status: StatusServFail}
	}
	msg, raw, err := c.exchangeUDP(ctx, packet, id)
	if err == nil && msg != nil && msg.Truncated {
		if tcpMsg, tcpRaw, tcpErr := c.exchangeTCP(ctx, packet, id); tcpErr == nil {
			msg, raw = tcpMsg, tcpRaw
		}
	}
	if err != nil {
		return Answer{Status: StatusTimeout}
	}
	switch msg.RCode {
	case dnswire.RCodeNoError:
		return Answer{Status: StatusOK, Msg: msg, Raw: raw}
	case dnswire.RCodeNXDomain:
		return Answer{Status: StatusNXDomain, Msg: msg, Raw: raw}
	default:
		return Answer{Status: StatusServFail, Msg: msg, Raw: raw}
	}
}

func (c *Client) dialer(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.Timeout)
}

func (c *Client) exchangeUDP(ctx context.Context, packet []byte, id uint16) (*dnswire.Msg, []byte, error) {
	ctx, cancel := c.dialer(ctx)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", c.Server.String())
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(packet); err != nil {
		return nil, nil, err
	}
	buf := make([]byte, maxUDPResponse)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, nil, err
		}

		raw := make([]byte, n)
		copy(raw, buf[:n])
		msg, err := dnswire.Unpack(raw)
		if err != nil {
			return nil, nil, err
		}

		if msg.ID != id {
			continue
		}
		return msg, raw, nil
	}
}

func (c *Client) exchangeTCP(ctx context.Context, packet []byte, id uint16) (*dnswire.Msg, []byte, error) {
	ctx, cancel := c.dialer(ctx)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", c.Server.String())
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	framed := make([]byte, 2+len(packet))
	binary.BigEndian.PutUint16(framed, uint16(len(packet)))
	copy(framed[2:], packet)
	if _, err := conn.Write(framed); err != nil {
		return nil, nil, err
	}
	head := make([]byte, 2)
	if _, err := readFull(conn, head); err != nil {
		return nil, nil, err
	}
	size := int(binary.BigEndian.Uint16(head))
	body := make([]byte, size)
	if _, err := readFull(conn, body); err != nil {
		return nil, nil, err
	}
	msg, err := dnswire.Unpack(body)
	if err != nil {
		return nil, nil, err
	}
	if msg.ID != id {
		return nil, nil, errors.New("DNS 应答 ID 不匹配")
	}
	return msg, body, nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func Addresses(a Answer) ([]netip.Addr, []netip.Addr) {
	if a.Status != StatusOK || a.Msg == nil {
		return nil, nil
	}
	var v4, v6 []netip.Addr
	for _, rr := range a.Msg.Answers {
		if addr, ok := rr.A(); ok {
			v4 = append(v4, addr)
		}
		if addr, ok := rr.AAAA(); ok {
			v6 = append(v6, addr)
		}
	}
	return v4, v6
}

func TargetNames(a Answer, rtype uint16) []string {
	if a.Status != StatusOK || a.Msg == nil {
		return nil
	}
	var out []string
	for _, rr := range a.Msg.Answers {
		if rr.Type != rtype {
			continue
		}
		if name, ok := rr.TargetName(a.Raw); ok {
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		for _, rr := range a.Msg.Authorities {
			if rr.Type != rtype {
				continue
			}
			if name, ok := rr.TargetName(a.Raw); ok {
				out = append(out, name)
			}
		}
	}
	return out
}
