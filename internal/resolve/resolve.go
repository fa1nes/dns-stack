package resolve

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dns-stack/dns-stack/internal/dnswire"
)

const (
	MaxCNAMEDepth  = 16
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

const (
	ReasonAnswer    = "answer"
	ReasonNXDomain  = "nxdomain"
	ReasonNoData    = "nodata"
	ReasonCNAMELoop = "cname_loop"
	ReasonMaxDepth  = "max_depth"
	ReasonTimeout   = "timeout"
	ReasonServFail  = "servfail"
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
	id := randomID()
	packet, err := dnswire.BuildQuery(id, name, qtype)
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

func ServiceHints(answers ...Answer) ([]netip.Addr, []netip.Addr) {
	var v4, v6 []netip.Addr
	for _, a := range answers {
		if a.Status != StatusOK || a.Msg == nil {
			continue
		}
		for _, rr := range a.Msg.Answers {
			svcb, ok := rr.SVCB(a.Raw)
			if !ok {
				continue
			}
			v4 = append(v4, svcb.IPv4Hint...)
			v6 = append(v6, svcb.IPv6Hint...)
		}
	}
	return v4, v6
}

func ServiceTargets(answers ...Answer) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, a := range answers {
		if a.Status != StatusOK || a.Msg == nil {
			continue
		}
		for _, rr := range a.Msg.Answers {
			svcb, ok := rr.SVCB(a.Raw)
			if !ok {
				continue
			}
			target := dnswire.NormalizeName(svcb.Target)
			if target == "" {
				continue
			}
			if _, dup := seen[target]; dup {
				continue
			}
			seen[target] = struct{}{}
			out = append(out, target)
		}
	}
	return out
}

type Outcome struct {
	OK         bool
	Reason     string
	CNAMEChain []string
	A          []netip.Addr
	AAAA       []netip.Addr
}

func (o Outcome) FinalAddresses() []netip.Addr {
	out := make([]netip.Addr, 0, len(o.A)+len(o.AAAA))
	out = append(out, o.A...)
	out = append(out, o.AAAA...)
	return out
}

type addrSet struct {
	mu   sync.Mutex
	seen map[netip.Addr]struct{}
}

func newAddrSet() *addrSet {
	return &addrSet{seen: make(map[netip.Addr]struct{})}
}

func (s *addrSet) add(values ...netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range values {
		if v.IsValid() {
			s.seen[v.Unmap()] = struct{}{}
		}
	}
}

func (s *addrSet) sorted() []netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]netip.Addr, 0, len(s.seen))
	for v := range s.seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
	return out
}

func Chain(ctx context.Context, c *Client, domain string) Outcome {
	type item struct {
		name      string
		ancestors []string
	}
	var chain []string
	inChain := make(map[string]struct{})
	seen := make(map[string]struct{})
	v4 := newAddrSet()
	v6 := newAddrSet()
	failures := make(map[string]struct{})
	queue := []item{{name: dnswire.NormalizeName(domain)}}

	appendChain := func(name string) {
		if _, ok := inChain[name]; ok {
			return
		}
		inChain[name] = struct{}{}
		chain = append(chain, name)
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, ancestor := range current.ancestors {
			if ancestor == current.name {
				return Outcome{Reason: ReasonCNAMELoop, CNAMEChain: chain}
			}
		}
		if len(current.ancestors) >= MaxCNAMEDepth {
			return Outcome{Reason: ReasonMaxDepth, CNAMEChain: chain}
		}
		if _, ok := seen[current.name]; ok {
			continue
		}
		seen[current.name] = struct{}{}

		cname := c.Query(ctx, current.name, dnswire.TypeCNAME)
		switch cname.Status {
		case StatusTimeout:
			failures[ReasonTimeout] = struct{}{}
			continue
		case StatusServFail:
			failures[ReasonServFail] = struct{}{}
			continue
		case StatusNXDomain:
			failures[ReasonNXDomain] = struct{}{}
			continue
		}
		if targets := TargetNames(cname, dnswire.TypeCNAME); len(targets) > 0 {
			target := dnswire.NormalizeName(targets[0])
			appendChain(target)
			queue = append(queue, item{
				name:      target,
				ancestors: append(append([]string{}, current.ancestors...), current.name),
			})
			continue
		}

		var https, svcb, aAns, aaaaAns Answer
		var wg sync.WaitGroup
		wg.Add(4)
		go func() { defer wg.Done(); https = c.Query(ctx, current.name, dnswire.TypeHTTPS) }()
		go func() { defer wg.Done(); svcb = c.Query(ctx, current.name, dnswire.TypeSVCB) }()
		go func() { defer wg.Done(); aAns = c.Query(ctx, current.name, dnswire.TypeA) }()
		go func() { defer wg.Done(); aaaaAns = c.Query(ctx, current.name, dnswire.TypeAAAA) }()
		wg.Wait()

		a4, _ := Addresses(aAns)
		_, a6 := Addresses(aaaaAns)
		v4.add(a4...)
		v6.add(a6...)
		hint4, hint6 := ServiceHints(https, svcb)
		v4.add(hint4...)
		v6.add(hint6...)

		for _, target := range ServiceTargets(https, svcb) {
			appendChain(target)
			queue = append(queue, item{
				name:      target,
				ancestors: append(append([]string{}, current.ancestors...), current.name),
			})
		}

		for _, answer := range []Answer{aAns, aaaaAns} {
			switch answer.Status {
			case StatusTimeout:
				failures[ReasonTimeout] = struct{}{}
			case StatusServFail:
				failures[ReasonServFail] = struct{}{}
			case StatusNXDomain:
				failures[ReasonNXDomain] = struct{}{}
			}
		}
	}

	got4, got6 := v4.sorted(), v6.sorted()
	if len(got4) > 0 || len(got6) > 0 {
		return Outcome{OK: true, Reason: ReasonAnswer, CNAMEChain: chain, A: got4, AAAA: got6}
	}
	for _, reason := range []string{ReasonTimeout, ReasonServFail, ReasonNXDomain} {
		if _, ok := failures[reason]; ok {
			return Outcome{Reason: reason, CNAMEChain: chain}
		}
	}
	return Outcome{Reason: ReasonNoData, CNAMEChain: chain}
}
