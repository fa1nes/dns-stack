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

func TestChainFollowsCNAMEToFinalAddress(t *testing.T) {
	client := fakeServer(t, map[string]zone{
		"www.example.com": {records: map[uint16][]record{
			dnswire.TypeCNAME: {{dnswire.TypeCNAME, targetName("cdn.example.net")}},
		}},
		"cdn.example.net": {records: map[uint16][]record{
			dnswire.TypeA: {{dnswire.TypeA, ipv4("116.1.2.3")}},
		}},
	})
	got := Chain(context.Background(), client, "WWW.Example.com.")
	if !got.OK || got.Reason != ReasonAnswer {
		t.Fatalf("应拿到最终地址: %+v", got)
	}
	if want := []string{"116.1.2.3"}; !equal(addrStrings(got.A), want) {
		t.Fatalf("A 记录 = %v, 期望 %v", got.A, want)
	}
	if want := []string{"cdn.example.net"}; !equal(got.CNAMEChain, want) {
		t.Fatalf("CNAME 链 = %v, 期望 %v", got.CNAMEChain, want)
	}
}

func TestChainDetectsCNAMELoop(t *testing.T) {
	client := fakeServer(t, map[string]zone{
		"a.example": {records: map[uint16][]record{
			dnswire.TypeCNAME: {{dnswire.TypeCNAME, targetName("b.example")}},
		}},
		"b.example": {records: map[uint16][]record{
			dnswire.TypeCNAME: {{dnswire.TypeCNAME, targetName("a.example")}},
		}},
	})
	got := Chain(context.Background(), client, "a.example")
	if got.OK || got.Reason != ReasonCNAMELoop {
		t.Fatalf("应判为 CNAME 成环: %+v", got)
	}
}

func TestChainCollectsServiceHintsAndTargets(t *testing.T) {
	client := fakeServer(t, map[string]zone{
		"example.com": {records: map[uint16][]record{
			dnswire.TypeHTTPS: {{dnswire.TypeHTTPS, func(b *respBuilder) {
				b.buf = binary.BigEndian.AppendUint16(b.buf, 1)
				for _, label := range []string{"svc", "example", "net"} {
					b.buf = append(b.buf, byte(len(label)))
					b.buf = append(b.buf, label...)
				}
				b.buf = append(b.buf, 0)
				b.buf = binary.BigEndian.AppendUint16(b.buf, 4)
				b.buf = binary.BigEndian.AppendUint16(b.buf, 4)
				b.buf = append(b.buf, 116, 9, 9, 9)
			}}},
		}},
		"svc.example.net": {records: map[uint16][]record{
			dnswire.TypeA: {{dnswire.TypeA, ipv4("116.8.8.8")}},
		}},
	})
	got := Chain(context.Background(), client, "example.com")
	if !got.OK {
		t.Fatalf("应拿到地址: %+v", got)
	}

	if want := []string{"116.8.8.8", "116.9.9.9"}; !equal(addrStrings(got.A), want) {
		t.Fatalf("A 记录 = %v, 期望 %v", addrStrings(got.A), want)
	}
	if want := []string{"svc.example.net"}; !equal(got.CNAMEChain, want) {
		t.Fatalf("链 = %v, 期望 %v", got.CNAMEChain, want)
	}
}

func TestChainReasonsForFailures(t *testing.T) {
	cases := []struct {
		name   string
		zones  map[string]zone
		reason string
	}{
		{
			name: "nxdomain",
			zones: map[string]zone{
				"gone.example": {rcode: dnswire.RCodeNXDomain},
			},
			reason: ReasonNXDomain,
		},
		{
			name: "servfail",
			zones: map[string]zone{
				"broken.example": {rcode: dnswire.RCodeServFail},
			},
			reason: ReasonServFail,
		},
		{
			name: "nodata",
			zones: map[string]zone{
				"empty.example": {},
			},
			reason: ReasonNoData,
		},
		{
			name: "timeout",
			zones: map[string]zone{
				"black.example": {silent: true},
			},
			reason: ReasonTimeout,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := fakeServer(t, tc.zones)
			var name string
			for key := range tc.zones {
				name = key
			}
			got := Chain(context.Background(), client, name)
			if got.OK {
				t.Fatalf("不该判为成功: %+v", got)
			}
			if got.Reason != tc.reason {
				t.Fatalf("reason = %q, 期望 %q", got.Reason, tc.reason)
			}
		})
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
