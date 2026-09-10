package resolvetest

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/dns-stack/dns-stack/internal/dnswire"
	"github.com/dns-stack/dns-stack/internal/resolve"
)

type Zone struct {
	RCode   uint8
	Records map[uint16][]Record
	Silent  bool
}

type Record struct {
	Type  uint16
	RData func(*Builder)
}

type Builder struct {
	Buf     []byte
	offsets map[string]int
}

func (b *Builder) Name(value string) {
	value = dnswire.NormalizeName(value)
	if at, ok := b.offsets[value]; ok && value != "" {
		b.Buf = binary.BigEndian.AppendUint16(b.Buf, uint16(0xC000|at))
		return
	}
	if value == "" {
		b.Buf = append(b.Buf, 0)
		return
	}
	b.offsets[value] = len(b.Buf)
	b.RawName(value)
}

func (b *Builder) RawName(value string) {
	for _, label := range strings.Split(dnswire.NormalizeName(value), ".") {
		b.Buf = append(b.Buf, byte(len(label)))
		b.Buf = append(b.Buf, label...)
	}
	b.Buf = append(b.Buf, 0)
}

func (b *Builder) Uint16(v uint16) {
	b.Buf = binary.BigEndian.AppendUint16(b.Buf, v)
}

func (b *Builder) Bytes(v ...byte) {
	b.Buf = append(b.Buf, v...)
}

func A(values ...string) func(*Builder) {
	return func(b *Builder) {
		for _, v := range values {
			addr := netip.MustParseAddr(v).As4()
			b.Bytes(addr[:]...)
		}
	}
}

func AAAA(value string) func(*Builder) {
	return func(b *Builder) {
		addr := netip.MustParseAddr(value).As16()
		b.Bytes(addr[:]...)
	}
}

func Target(value string) func(*Builder) {
	return func(b *Builder) { b.Name(value) }
}

func Serve(t *testing.T, zones map[string]Zone) *resolve.Client {
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
			zone := zones[q.Name]
			if zone.Silent {
				continue
			}
			_, _ = conn.WriteToUDP(respond(query.ID, q, zone), from)
		}
	}()
	addr := conn.LocalAddr().(*net.UDPAddr)
	client, err := resolve.NewClient("127.0.0.1", addr.Port, 2*time.Second)
	if err != nil {
		t.Fatalf("NewClient 失败: %v", err)
	}
	return client
}

func respond(id uint16, q dnswire.Question, zone Zone) []byte {
	b := &Builder{offsets: make(map[string]int)}
	b.Uint16(id)
	b.Uint16(uint16(0x8180) | uint16(zone.RCode))
	b.Uint16(1)
	answerCountAt := len(b.Buf)
	b.Uint16(0)
	b.Uint16(0)
	b.Uint16(0)
	b.Name(q.Name)
	b.Uint16(q.Type)
	b.Uint16(dnswire.ClassIN)
	count := 0
	for _, rec := range zone.Records[q.Type] {
		b.Name(q.Name)
		b.Uint16(rec.Type)
		b.Uint16(dnswire.ClassIN)
		b.Buf = binary.BigEndian.AppendUint32(b.Buf, 60)
		lengthAt := len(b.Buf)
		b.Uint16(0)
		start := len(b.Buf)
		rec.RData(b)
		binary.BigEndian.PutUint16(b.Buf[lengthAt:], uint16(len(b.Buf)-start))
		count++
	}
	binary.BigEndian.PutUint16(b.Buf[answerCountAt:], uint16(count))
	return b.Buf
}
