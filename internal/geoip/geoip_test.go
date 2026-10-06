package geoip

import (
	"net/netip"
	"os"
	"testing"
)

func TestCarrierAndPlace(t *testing.T) {
	if MatchCarrier("China Education and Research Network") != "教育网" {
		t.Fatal("carrier")
	}
	if MatchCarrier("China Unicom Beijing") != "联通" {
		t.Fatal("unicom")
	}
	if MatchPlace("Tianjij,300000") != "天津" {
		t.Fatal("place")
	}
	if MatchPlace("mexian networks") != "" {
		t.Fatal("substring place")
	}
}

func TestMMDBProductionProbe(t *testing.T) {
	path := os.Getenv("GEOIP_DEBUG_ASN")
	if path == "" {
		t.Skip()
	}
	r, err := OpenMMDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	t.Logf("nodes=%d record=%d ip=%d base=%d", r.nodeCount, r.recordSize, r.ipVersion, r.dataBase)
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "114.114.114.114"} {
		v, err := r.Get(ip)
		t.Logf("%s %#v err=%v", ip, v, err)
	}
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "114.114.114.114"} {
		a := mustAddr16(ip)
		n := 0
		for i := 0; i < 128 && n < r.nodeCount; i++ {
			bit := int((a[i/8] >> uint(7-(i&7))) & 1)
			n, _ = r.readNode(n, bit)
		}
		off := n - r.nodeCount - 16 + r.dataBase
		t.Logf("node %s=%d off=%d bytes=% x", ip, n, off, r.data[off:off+8])
	}
}

func mustAddr16(s string) [16]byte {
	a, _ := netip.ParseAddr(s)
	var p [16]byte
	if a.Is4() {
		p[10], p[11] = 0xff, 0xff
		v := a.As4()
		copy(p[12:], v[:])
		return p
	}
	return a.As16()
}
