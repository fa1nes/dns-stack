package dnswire

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

type builder struct {
	buf     []byte
	offsets map[string]int
}

func newBuilder(id uint16, rcode uint8, qname string, qtype uint16) *builder {
	b := &builder{offsets: make(map[string]int)}
	b.buf = binary.BigEndian.AppendUint16(b.buf, id)
	b.buf = binary.BigEndian.AppendUint16(b.buf, uint16(0x8180)|uint16(rcode))
	b.buf = binary.BigEndian.AppendUint16(b.buf, 1)
	b.buf = binary.BigEndian.AppendUint16(b.buf, 0)
	b.buf = binary.BigEndian.AppendUint16(b.buf, 0)
	b.buf = binary.BigEndian.AppendUint16(b.buf, 0)
	b.appendName(qname)
	b.buf = binary.BigEndian.AppendUint16(b.buf, qtype)
	b.buf = binary.BigEndian.AppendUint16(b.buf, ClassIN)
	return b
}

func (b *builder) appendName(name string) {
	name = NormalizeName(name)
	if at, ok := b.offsets[name]; ok && name != "" {
		b.buf = binary.BigEndian.AppendUint16(b.buf, uint16(0xC000|at))
		return
	}
	if name != "" {
		b.offsets[name] = len(b.buf)
	}
	out, err := appendName(nil, name)
	if err != nil {
		panic(err)
	}
	b.buf = append(b.buf, out...)
}

func (b *builder) addAnswer(name string, rtype uint16, rdata func(*builder)) {
	b.appendName(name)
	b.buf = binary.BigEndian.AppendUint16(b.buf, rtype)
	b.buf = binary.BigEndian.AppendUint16(b.buf, ClassIN)
	b.buf = binary.BigEndian.AppendUint32(b.buf, 300)
	lengthAt := len(b.buf)
	b.buf = binary.BigEndian.AppendUint16(b.buf, 0)
	start := len(b.buf)
	rdata(b)
	binary.BigEndian.PutUint16(b.buf[lengthAt:], uint16(len(b.buf)-start))
	count := binary.BigEndian.Uint16(b.buf[6:8])
	binary.BigEndian.PutUint16(b.buf[6:8], count+1)
}

func TestUnpackAddressesAndTargets(t *testing.T) {
	b := newBuilder(0x1234, RCodeNoError, "www.example.com", TypeA)
	b.addAnswer("www.example.com", TypeCNAME, func(bb *builder) {
		bb.appendName("cdn.example.net")
	})
	b.addAnswer("cdn.example.net", TypeA, func(bb *builder) {
		bb.buf = append(bb.buf, 116, 1, 2, 3)
	})
	b.addAnswer("cdn.example.net", TypeAAAA, func(bb *builder) {
		addr := netip.MustParseAddr("2400:3200::1").As16()
		bb.buf = append(bb.buf, addr[:]...)
	})

	msg, err := Unpack(b.buf)
	if err != nil {
		t.Fatalf("Unpack 失败: %v", err)
	}
	if msg.ID != 0x1234 || !msg.Response || msg.RCode != RCodeNoError {
		t.Fatalf("报文头解析错误: %+v", msg)
	}
	if len(msg.Questions) != 1 || msg.Questions[0].Name != "www.example.com" {
		t.Fatalf("问题段解析错误: %+v", msg.Questions)
	}
	if len(msg.Answers) != 3 {
		t.Fatalf("应答段应有 3 条，实际 %d", len(msg.Answers))
	}
	if name, ok := msg.Answers[0].TargetName(b.buf); !ok || name != "cdn.example.net" {
		t.Fatalf("CNAME 目标解析错误: %q ok=%v", name, ok)
	}
	if addr, ok := msg.Answers[1].A(); !ok || addr.String() != "116.1.2.3" {
		t.Fatalf("A 记录解析错误: %v ok=%v", addr, ok)
	}
	if addr, ok := msg.Answers[2].AAAA(); !ok || addr.String() != "2400:3200::1" {
		t.Fatalf("AAAA 记录解析错误: %v ok=%v", addr, ok)
	}

	if _, ok := msg.Answers[2].A(); ok {
		t.Fatal("AAAA 记录不该被 A() 接受")
	}
}

func TestUnpackSVCBHints(t *testing.T) {
	b := newBuilder(1, RCodeNoError, "example.com", TypeHTTPS)
	b.addAnswer("example.com", TypeHTTPS, func(bb *builder) {
		bb.buf = binary.BigEndian.AppendUint16(bb.buf, 1)

		out, err := appendName(nil, "svc.example.net")
		if err != nil {
			t.Fatalf("appendName 失败: %v", err)
		}
		bb.buf = append(bb.buf, out...)
		bb.buf = binary.BigEndian.AppendUint16(bb.buf, 1)
		bb.buf = binary.BigEndian.AppendUint16(bb.buf, 3)
		bb.buf = append(bb.buf, 2, 'h', '2')
		bb.buf = binary.BigEndian.AppendUint16(bb.buf, 4)
		bb.buf = binary.BigEndian.AppendUint16(bb.buf, 8)
		bb.buf = append(bb.buf, 1, 1, 1, 1, 116, 5, 6, 7)
		bb.buf = binary.BigEndian.AppendUint16(bb.buf, 6)
		bb.buf = binary.BigEndian.AppendUint16(bb.buf, 16)
		addr := netip.MustParseAddr("2606:4700::1").As16()
		bb.buf = append(bb.buf, addr[:]...)
	})

	msg, err := Unpack(b.buf)
	if err != nil {
		t.Fatalf("Unpack 失败: %v", err)
	}
	svcb, ok := msg.Answers[0].SVCB(b.buf)
	if !ok {
		t.Fatal("SVCB 解析失败")
	}
	if svcb.Priority != 1 || svcb.Target != "svc.example.net" {
		t.Fatalf("SVCB 头解析错误: %+v", svcb)
	}
	if len(svcb.IPv4Hint) != 2 || svcb.IPv4Hint[0].String() != "1.1.1.1" ||
		svcb.IPv4Hint[1].String() != "116.5.6.7" {
		t.Fatalf("ipv4hint 解析错误: %v", svcb.IPv4Hint)
	}
	if len(svcb.IPv6Hint) != 1 || svcb.IPv6Hint[0].String() != "2606:4700::1" {
		t.Fatalf("ipv6hint 解析错误: %v", svcb.IPv6Hint)
	}
}

func TestUnpackRejectsMalformedMessages(t *testing.T) {
	if _, err := Unpack([]byte{1, 2, 3}); err == nil {
		t.Fatal("过短报文应报错")
	}

	loop := []byte{
		0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0,
		0xC0, 0x0C,
	}
	if _, err := Unpack(loop); err == nil {
		t.Fatal("自指压缩指针应报错")
	}
}

func TestBuildQueryCarriesEDNS0(t *testing.T) {
	packet, err := BuildQuery(0xABCD, "Example.COM.", TypeA)
	if err != nil {
		t.Fatalf("BuildQuery 失败: %v", err)
	}
	msg, err := Unpack(packet)
	if err != nil {
		t.Fatalf("自产报文无法回读: %v", err)
	}
	if msg.ID != 0xABCD {
		t.Fatalf("ID 不符: %#x", msg.ID)
	}
	if len(msg.Questions) != 1 || msg.Questions[0].Name != "example.com" {
		t.Fatalf("查询名未规范化: %+v", msg.Questions)
	}
	if len(msg.Additionals) != 1 || msg.Additionals[0].Type != TypeOPT {
		t.Fatalf("缺少 EDNS0 OPT: %+v", msg.Additionals)
	}
	if msg.Additionals[0].Class != udpPayloadSize {
		t.Fatalf("OPT 载荷大小应为 %d，实际 %d", udpPayloadSize, msg.Additionals[0].Class)
	}
}

func TestNameHelpers(t *testing.T) {
	if got := NormalizeName("  WWW.Example.COM.  "); got != "www.example.com" {
		t.Fatalf("NormalizeName = %q", got)
	}
	if got := TypeName(TypeHTTPS); got != "HTTPS" {
		t.Fatalf("TypeName(HTTPS) = %q", got)
	}
	if got := TypeName(9999); got != "TYPE9999" {
		t.Fatalf("未知类型应回报数字，实际 %q", got)
	}
	if _, ok := TypeByName("mx"); ok {
		t.Fatal("未支持的类型不该被接受")
	}
	if v, ok := TypeByName(" aaaa "); !ok || v != TypeAAAA {
		t.Fatalf("TypeByName(aaaa) = %d ok=%v", v, ok)
	}
	if _, err := appendName(nil, "a..b"); err == nil {
		t.Fatal("空标签应报错")
	}
}
