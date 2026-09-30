package resolve

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/dns-stack/dns-stack/internal/dnswire"
)

type record struct {
	rtype uint16
	rdata func(*respBuilder)
}

type zone struct {
	rcode   uint8
	records map[uint16][]record
	silent  bool
}

type respBuilder struct {
	buf     []byte
	offsets map[string]int
}

func (b *respBuilder) name(value string) {
	value = dnswire.NormalizeName(value)
	if at, ok := b.offsets[value]; ok && value != "" {
		b.buf = binary.BigEndian.AppendUint16(b.buf, uint16(0xC000|at))
		return
	}
	if value != "" {
		b.offsets[value] = len(b.buf)
	}
	if value == "" {
		b.buf = append(b.buf, 0)
		return
	}
	for _, label := range strings.Split(value, ".") {
		b.buf = append(b.buf, byte(len(label)))
		b.buf = append(b.buf, label...)
	}
	b.buf = append(b.buf, 0)
}

func ipv4(values ...string) func(*respBuilder) {
	return func(b *respBuilder) {
		for _, v := range values {
			addr := netip.MustParseAddr(v).As4()
			b.buf = append(b.buf, addr[:]...)
		}
	}
}

func targetName(value string) func(*respBuilder) {
	return func(b *respBuilder) { b.name(value) }
}

func fakeServer(t *testing.T, zones map[string]zone) *Client {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			query, err := dnswire.Unpack(buf[:n])
			if err != nil || len(query.Questions) == 0 {
				continue
			}
			q := query.Questions[0]
			z := zones[q.Name]
			if z.silent {
				continue
			}
			b := &respBuilder{offsets: make(map[string]int)}
			b.buf = binary.BigEndian.AppendUint16(b.buf, query.ID)
			b.buf = binary.BigEndian.AppendUint16(b.buf, uint16(0x8180)|uint16(z.rcode))
			b.buf = binary.BigEndian.AppendUint16(b.buf, 1)
			answerCountAt := len(b.buf)
			b.buf = binary.BigEndian.AppendUint16(b.buf, 0)
			b.buf = binary.BigEndian.AppendUint16(b.buf, 0)
			b.buf = binary.BigEndian.AppendUint16(b.buf, 0)
			b.name(q.Name)
			b.buf = binary.BigEndian.AppendUint16(b.buf, q.Type)
			b.buf = binary.BigEndian.AppendUint16(b.buf, dnswire.ClassIN)
			count := 0
			for _, rec := range z.records[q.Type] {
				b.name(q.Name)
				b.buf = binary.BigEndian.AppendUint16(b.buf, rec.rtype)
				b.buf = binary.BigEndian.AppendUint16(b.buf, dnswire.ClassIN)
				b.buf = binary.BigEndian.AppendUint32(b.buf, 60)
				lengthAt := len(b.buf)
				b.buf = binary.BigEndian.AppendUint16(b.buf, 0)
				start := len(b.buf)
				rec.rdata(b)
				binary.BigEndian.PutUint16(b.buf[lengthAt:], uint16(len(b.buf)-start))
				count++
			}
			binary.BigEndian.PutUint16(b.buf[answerCountAt:], uint16(count))
			_, _ = conn.WriteToUDP(b.buf, from)
		}
	}()
	addr := conn.LocalAddr().(*net.UDPAddr)
	client, err := NewClient("127.0.0.1", addr.Port, 2*time.Second)
	if err != nil {
		t.Fatalf("NewClient 失败: %v", err)
	}
	return client
}

func addrStrings(values []netip.Addr) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, v.String())
	}
	return out
}

func TestQueryDecodesCNAMETargetAndAddressesOverTheWire(t *testing.T) {
	client := fakeServer(t, map[string]zone{
		"www.example.com": {records: map[uint16][]record{
			dnswire.TypeCNAME: {{dnswire.TypeCNAME, targetName("cdn.example.net")}},
		}},
		"cdn.example.net": {records: map[uint16][]record{
			dnswire.TypeA: {{dnswire.TypeA, ipv4("116.1.2.3")}, {dnswire.TypeA, ipv4("116.1.2.4")}},
		}},
	})
	cname := client.Query(context.Background(), "WWW.Example.com.", dnswire.TypeCNAME)
	if cname.Status != StatusOK {
		t.Fatalf("CNAME 查询状态 = %v，期望 StatusOK", cname.Status)
	}
	if got, want := TargetNames(cname, dnswire.TypeCNAME), []string{"cdn.example.net"}; !equal(got, want) {
		t.Fatalf("TargetNames = %v, 期望 %v——authority 与 opsctl 都靠它顺着 CNAME 往下走", got, want)
	}
	a := client.Query(context.Background(), "cdn.example.net", dnswire.TypeA)
	v4, v6 := Addresses(a)
	if got, want := addrStrings(v4), []string{"116.1.2.3", "116.1.2.4"}; !equal(got, want) || len(v6) != 0 {
		t.Fatalf("Addresses = %v / %v, 期望 %v / []", got, addrStrings(v6), want)
	}
}

func TestQueryMapsResponseCodesToStatus(t *testing.T) {
	client := fakeServer(t, map[string]zone{
		"gone.example":   {rcode: dnswire.RCodeNXDomain},
		"broken.example": {rcode: 2},
		"quiet.example":  {silent: true},
	})
	for _, tc := range []struct {
		name string
		want Status
	}{
		{"gone.example", StatusNXDomain},
		{"broken.example", StatusServFail},
		{"quiet.example", StatusTimeout},
	} {
		got := client.Query(context.Background(), tc.name, dnswire.TypeA)
		if got.Status != tc.want {
			t.Errorf("%s: Status = %v, 期望 %v——调用方靠这个区分「域名不存在」「上游坏了」「没回应」，"+
				"混为一谈会让污染采集和权威判定把故障当成证据", tc.name, got.Status, tc.want)
		}
		if v4, v6 := Addresses(got); len(v4)+len(v6) != 0 {
			t.Errorf("%s: 失败的应答不该产出任何地址，却给出了 %v %v", tc.name, v4, v6)
		}
	}
}

func TestNewClientRejectsBadInput(t *testing.T) {
	if _, err := NewClient("not-an-ip", 53, time.Second); err == nil {
		t.Fatal("非法地址应报错")
	}
	if _, err := NewClient("127.0.0.1", 0, time.Second); err == nil {
		t.Fatal("非法端口应报错")
	}
	c, err := NewClient("127.0.0.1", 53, 0)
	if err != nil {
		t.Fatalf("零超时应回落到默认值: %v", err)
	}
	if c.Timeout != DefaultTimeout {
		t.Fatalf("Timeout = %v, 期望 %v", c.Timeout, DefaultTimeout)
	}
}

func equal(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
