package infra

import (
	"strings"
	"testing"
)

func TestParseFieldsAndAddresses(t *testing.T) {
	text := strings.Join([]string{
		"108.162.198.251 cloudflare.net. ttl 2681 rto 250 ping 26",
		"2a00:86c0:2009::1 nflxso.net. rto 376 ttl 2365",
		"1.1.1.1 . ttl 1 rto 2",
		"bad.example ttl 1 rto 2",
		"8.8.8.8 malformed ttl 1 rto 3",
		"",
	}, "\n")
	s, err := Parse(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Entries) != 2 || s.Skipped != 3 {
		t.Fatalf("entries=%d skipped=%d", len(s.Entries), s.Skipped)
	}
	if s.Entries[0].Zone != "cloudflare.net" || !s.Entries[0].HasRTO || s.Entries[0].RTO != 250 {
		t.Fatalf("unexpected first entry: %#v", s.Entries[0])
	}
	if s.Entries[1].Zone != "nflxso.net" || !s.Entries[1].IP.Is6() || !s.Entries[1].HasRTO || s.Entries[1].RTO != 376 {
		t.Fatalf("unexpected second entry: %#v", s.Entries[1])
	}
}

func TestPairsAndZonesDeduplicateByContract(t *testing.T) {
	text := strings.Join([]string{
		"1.1.1.1 Example.COM. rto 20",
		"1.1.1.1 example.com. rto 20",
		"1.1.1.1 example.com. rto 30",
		"2.2.2.2 example.com. rto 10",
	}, "\n")
	s, err := Parse(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(s.Pairs()); got != 3 {
		t.Fatalf("pairs=%d", got)
	}
	zones := s.Zones()
	if len(zones) != 1 || len(zones["example.com"]) != 2 {
		t.Fatalf("zones=%#v", zones)
	}
}

func TestRTOMissingIsFailOpenSignal(t *testing.T) {
	s, err := Parse(strings.NewReader("1.1.1.1 example.com. ttl 1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Entries) != 1 || s.Entries[0].HasRTO {
		t.Fatalf("entry=%#v", s.Entries)
	}
}
