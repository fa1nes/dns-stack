package dnswire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypeAAAA  uint16 = 28
	TypeOPT   uint16 = 41
	TypeSVCB  uint16 = 64
	TypeHTTPS uint16 = 65
)

const ClassIN uint16 = 1

const (
	RCodeNoError  uint8 = 0
	RCodeFormErr  uint8 = 1
	RCodeServFail uint8 = 2
	RCodeNXDomain uint8 = 3
	RCodeNotImp   uint8 = 4
	RCodeRefused  uint8 = 5
)

const (
	svcParamIPv4Hint uint16 = 4
	svcParamIPv6Hint uint16 = 6
)

const (
	maxNamePointers = 32
	maxNameLength   = 255
	maxLabelLength  = 63
	udpPayloadSize  = 1232
)

var (
	ErrTruncatedMessage = errors.New("DNS 报文被截断")
	ErrBadName          = errors.New("DNS 名称格式错误")
	ErrNamePointerLoop  = errors.New("DNS 名称压缩指针成环")
)

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

type RR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  []byte

	RDataAt int
}

type Msg struct {
	ID          uint16
	Response    bool
	Truncated   bool
	RCode       uint8
	Questions   []Question
	Answers     []RR
	Authorities []RR
	Additionals []RR
}

func TypeName(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypeAAAA:
		return "AAAA"
	case TypeSVCB:
		return "SVCB"
	case TypeHTTPS:
		return "HTTPS"
	}
	return fmt.Sprintf("TYPE%d", t)
}

func TypeByName(name string) (uint16, bool) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "A":
		return TypeA, true
	case "NS":
		return TypeNS, true
	case "CNAME":
		return TypeCNAME, true
	case "SOA":
		return TypeSOA, true
	case "AAAA":
		return TypeAAAA, true
	case "SVCB":
		return TypeSVCB, true
	case "HTTPS":
		return TypeHTTPS, true
	}
	return 0, false
}

func NormalizeName(name string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(name), "."))
}

func appendName(b []byte, name string) ([]byte, error) {
	name = NormalizeName(name)
	if name == "" {
		return append(b, 0), nil
	}
	if len(name) > maxNameLength {
		return nil, ErrBadName
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > maxLabelLength {
			return nil, ErrBadName
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0), nil
}

func BuildQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	b := make([]byte, 0, 64)
	b = binary.BigEndian.AppendUint16(b, id)
	b = binary.BigEndian.AppendUint16(b, 0x0100)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint16(b, 0)
	b = binary.BigEndian.AppendUint16(b, 0)
	b = binary.BigEndian.AppendUint16(b, 1)
	var err error
	if b, err = appendName(b, name); err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, ClassIN)
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, TypeOPT)
	b = binary.BigEndian.AppendUint16(b, udpPayloadSize)
	b = binary.BigEndian.AppendUint32(b, 0)
	b = binary.BigEndian.AppendUint16(b, 0)
	return b, nil
}

type parser struct {
	buf []byte
	off int
}

func (p *parser) uint16() (uint16, error) {
	if p.off+2 > len(p.buf) {
		return 0, ErrTruncatedMessage
	}
	v := binary.BigEndian.Uint16(p.buf[p.off:])
	p.off += 2
	return v, nil
}

func (p *parser) uint32() (uint32, error) {
	if p.off+4 > len(p.buf) {
		return 0, ErrTruncatedMessage
	}
	v := binary.BigEndian.Uint32(p.buf[p.off:])
	p.off += 4
	return v, nil
}

func (p *parser) name() (string, error) {
	var labels []string
	off := p.off
	end := -1
	pointers := 0
	total := 0
	for {
		if off >= len(p.buf) {
			return "", ErrTruncatedMessage
		}
		n := int(p.buf[off])
		switch {
		case n == 0:
			off++
			if end < 0 {
				end = off
			}
			p.off = end
			return strings.ToLower(strings.Join(labels, ".")), nil
		case n&0xC0 == 0xC0:
			if off+2 > len(p.buf) {
				return "", ErrTruncatedMessage
			}
			target := int(binary.BigEndian.Uint16(p.buf[off:]) & 0x3FFF)
			if end < 0 {
				end = off + 2
			}
			pointers++
			if pointers > maxNamePointers || target >= off {
				return "", ErrNamePointerLoop
			}
			off = target
		case n&0xC0 != 0:
			return "", ErrBadName
		default:
			if off+1+n > len(p.buf) {
				return "", ErrTruncatedMessage
			}
			total += n + 1
			if total > maxNameLength {
				return "", ErrBadName
			}
			labels = append(labels, string(p.buf[off+1:off+1+n]))
			off += 1 + n
		}
	}
}

func (p *parser) question() (Question, error) {
	name, err := p.name()
	if err != nil {
		return Question{}, err
	}
	qtype, err := p.uint16()
	if err != nil {
		return Question{}, err
	}
	qclass, err := p.uint16()
	if err != nil {
		return Question{}, err
	}
	return Question{Name: name, Type: qtype, Class: qclass}, nil
}

func (p *parser) rr() (RR, error) {
	name, err := p.name()
	if err != nil {
		return RR{}, err
	}
	rtype, err := p.uint16()
	if err != nil {
		return RR{}, err
	}
	rclass, err := p.uint16()
	if err != nil {
		return RR{}, err
	}
	ttl, err := p.uint32()
	if err != nil {
		return RR{}, err
	}
	length, err := p.uint16()
	if err != nil {
		return RR{}, err
	}
	if p.off+int(length) > len(p.buf) {
		return RR{}, ErrTruncatedMessage
	}
	at := p.off
	data := p.buf[p.off : p.off+int(length)]
	p.off += int(length)
	return RR{Name: name, Type: rtype, Class: rclass, TTL: ttl, Data: data, RDataAt: at}, nil
}

func Unpack(buf []byte) (*Msg, error) {
	if len(buf) < 12 {
		return nil, ErrTruncatedMessage
	}
	p := &parser{buf: buf}
	id, _ := p.uint16()
	flags, _ := p.uint16()
	qd, _ := p.uint16()
	an, _ := p.uint16()
	ns, _ := p.uint16()
	ar, _ := p.uint16()
	m := &Msg{
		ID:        id,
		Response:  flags&0x8000 != 0,
		Truncated: flags&0x0200 != 0,
		RCode:     uint8(flags & 0x000F),
	}
	for i := 0; i < int(qd); i++ {
		q, err := p.question()
		if err != nil {
			return nil, err
		}
		m.Questions = append(m.Questions, q)
	}
	for _, target := range []struct {
		count uint16
		dst   *[]RR
	}{{an, &m.Answers}, {ns, &m.Authorities}, {ar, &m.Additionals}} {
		for i := 0; i < int(target.count); i++ {
			rr, err := p.rr()
			if err != nil {
				if m.Truncated {
					return m, nil
				}
				return nil, err
			}
			*target.dst = append(*target.dst, rr)
		}
	}
	return m, nil
}

func NameInRDATA(msg []byte, rdataAt, at int) (string, error) {
	if rdataAt < 0 || at < 0 || rdataAt+at > len(msg) {
		return "", ErrTruncatedMessage
	}
	p := &parser{buf: msg, off: rdataAt + at}
	return p.name()
}

func (r RR) addr(want int) (netip.Addr, bool) {
	if len(r.Data) != want {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(r.Data)
	if !ok {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func (r RR) A() (netip.Addr, bool) {
	if r.Type != TypeA {
		return netip.Addr{}, false
	}
	return r.addr(4)
}

func (r RR) AAAA() (netip.Addr, bool) {
	if r.Type != TypeAAAA {
		return netip.Addr{}, false
	}
	return r.addr(16)
}

func (r RR) TargetName(msg []byte) (string, bool) {
	switch r.Type {
	case TypeNS, TypeCNAME, TypeSOA:
		name, err := NameInRDATA(msg, r.RDataAt, 0)
		if err != nil || name == "" {
			return "", false
		}
		return name, true
	}
	return "", false
}

type SVCB struct {
	Priority uint16
	Target   string
	IPv4Hint []netip.Addr
	IPv6Hint []netip.Addr
}

func (r RR) SVCB(msg []byte) (SVCB, bool) {
	if r.Type != TypeSVCB && r.Type != TypeHTTPS {
		return SVCB{}, false
	}
	if len(r.Data) < 3 {
		return SVCB{}, false
	}
	out := SVCB{Priority: binary.BigEndian.Uint16(r.Data[:2])}
	target, err := NameInRDATA(msg, r.RDataAt, 2)
	if err != nil {
		return SVCB{}, false
	}
	out.Target = target

	consumed := 2 + wireNameLength(r.Data[2:])
	if consumed <= 2 || consumed > len(r.Data) {
		return out, true
	}
	rest := r.Data[consumed:]
	for len(rest) >= 4 {
		key := binary.BigEndian.Uint16(rest[:2])
		length := int(binary.BigEndian.Uint16(rest[2:4]))
		rest = rest[4:]
		if length > len(rest) {
			break
		}
		value := rest[:length]
		rest = rest[length:]
		switch key {
		case svcParamIPv4Hint:
			for i := 0; i+4 <= len(value); i += 4 {
				if addr, ok := netip.AddrFromSlice(value[i : i+4]); ok {
					out.IPv4Hint = append(out.IPv4Hint, addr.Unmap())
				}
			}
		case svcParamIPv6Hint:
			for i := 0; i+16 <= len(value); i += 16 {
				if addr, ok := netip.AddrFromSlice(value[i : i+16]); ok {
					out.IPv6Hint = append(out.IPv6Hint, addr.Unmap())
				}
			}
		}
	}
	return out, true
}

func wireNameLength(b []byte) int {
	n := 0
	for n < len(b) {
		l := int(b[n])
		if l == 0 {
			return n + 1
		}
		if l&0xC0 != 0 {
			return n + 2
		}
		n += 1 + l
	}
	return 0
}
