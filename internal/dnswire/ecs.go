package dnswire

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	OptCodeClientSubnet uint16 = 8
	familyIPv4          uint16 = 1
	familyIPv6          uint16 = 2
)

var ErrBadSubnet = errors.New("ECS 前缀必须是有效的 IPv4/IPv6 网段")

func BuildQueryWithSubnet(id uint16, name string, qtype uint16, subnet netip.Prefix) ([]byte, error) {
	if !subnet.IsValid() {
		return nil, ErrBadSubnet
	}
	subnet = subnet.Masked()
	family, addr := familyIPv4, subnet.Addr().Unmap()
	if addr.Is6() {
		family = familyIPv6
	}
	bits := subnet.Bits()
	if bits < 0 || bits > addr.BitLen() {
		return nil, ErrBadSubnet
	}
	significant := (bits + 7) / 8
	raw := addr.AsSlice()
	if significant > len(raw) {
		return nil, ErrBadSubnet
	}

	option := make([]byte, 0, 8+significant)
	option = binary.BigEndian.AppendUint16(option, OptCodeClientSubnet)
	option = binary.BigEndian.AppendUint16(option, uint16(4+significant))
	option = binary.BigEndian.AppendUint16(option, family)
	option = append(option, byte(bits), 0)
	option = append(option, raw[:significant]...)

	b := make([]byte, 0, 64+len(option))
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
	b = binary.BigEndian.AppendUint16(b, uint16(len(option)))
	return append(b, option...), nil
}

type ClientSubnet struct {
	Prefix netip.Prefix
	Scope  int
}

func (m *Msg) ClientSubnet() (ClientSubnet, bool) {
	for _, rr := range m.Additionals {
		if rr.Type != TypeOPT {
			continue
		}
		data := rr.Data
		for len(data) >= 4 {
			code := binary.BigEndian.Uint16(data)
			length := int(binary.BigEndian.Uint16(data[2:]))
			if len(data) < 4+length {
				return ClientSubnet{}, false
			}
			if code == OptCodeClientSubnet && length >= 4 {
				return decodeClientSubnet(data[4 : 4+length])
			}
			data = data[4+length:]
		}
	}
	return ClientSubnet{}, false
}

func decodeClientSubnet(body []byte) (ClientSubnet, bool) {
	family := binary.BigEndian.Uint16(body)
	sourceBits := int(body[2])
	scope := int(body[3])
	size := 4
	if family == familyIPv6 {
		size = 16
	} else if family != familyIPv4 {
		return ClientSubnet{}, false
	}
	buf := make([]byte, size)
	copy(buf, body[4:])
	addr, ok := netip.AddrFromSlice(buf)
	if !ok || sourceBits > addr.BitLen() {
		return ClientSubnet{}, false
	}
	return ClientSubnet{Prefix: netip.PrefixFrom(addr, sourceBits), Scope: scope}, true
}
