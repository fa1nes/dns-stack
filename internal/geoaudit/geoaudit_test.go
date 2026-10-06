package geoaudit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func spans(values ...[2]uint32) []Span {
	out := make([]Span, 0, len(values))
	for _, v := range values {
		out = append(out, Span{Lo: v[0], Hi: v[1], Country: "US"})
	}
	return out
}

func TestMergeAgreementNeedsEnoughSources(t *testing.T) {
	a := spans([2]uint32{100, 200})
	b := spans([2]uint32{150, 250})
	c := spans([2]uint32{180, 300})

	one, total := mergeAgreement([][]Span{a, b, c}, 1)
	if len(one) != 1 || one[0].Lo != 100 || one[0].Hi != 300 || total != 201 {
		t.Fatalf("need=1: %#v total=%d", one, total)
	}
	two, twoTotal := mergeAgreement([][]Span{a, b, c}, 2)
	if len(two) != 1 || two[0].Lo != 150 || two[0].Hi != 250 || twoTotal != 101 {
		t.Fatalf("need=2: %#v total=%d", two, twoTotal)
	}
	three, _ := mergeAgreement([][]Span{a, b, c}, 3)
	if len(three) != 1 || three[0].Lo != 180 || three[0].Hi != 200 {
		t.Fatalf("need=3: %#v", three)
	}
}

func TestMergeAgreementIgnoresLoneSource(t *testing.T) {
	only := spans([2]uint32{10, 20})
	out, total := mergeAgreement([][]Span{only}, 2)
	if len(out) != 0 || total != 0 {
		t.Fatalf("单个源不得达成一致: %#v total=%d", out, total)
	}
}

func TestSnapshotRoundTripCarriesKind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geo-disputed.txt")
	if err := Write(path, KindDisputed, 2, []string{"qqwry", "dbip"},
		[]Span{{Lo: 0x01010100, Hi: 0x010101ff, Country: "US"}}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := LoadSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Kind != KindDisputed {
		t.Fatalf("kind=%q", snapshot.Kind)
	}
	if snapshot.Agreement != 2 {
		t.Fatalf("agreement=%d", snapshot.Agreement)
	}
	if len(snapshot.Sources) != 2 || snapshot.Sources[0] != "qqwry" {
		t.Fatalf("sources=%v", snapshot.Sources)
	}
	if snapshot.Set.AddressCount() != 256 {
		t.Fatalf("addresses=%d", snapshot.Set.AddressCount())
	}
	if snapshot.Age(time.Now()) > time.Minute {
		t.Fatalf("age=%v", snapshot.Age(time.Now()))
	}
}

func TestSnapshotDropsNonGlobalPrefixes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.txt")
	body := "# kind disputed\n# agreement 2\n10.0.0.0/8\n192.168.0.0/16\n1.1.1.0/24\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot, err := LoadSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Set.AddressCount() != 256 {
		t.Fatalf("非全局网段必须被丢弃，实际覆盖 %d 个地址", snapshot.Set.AddressCount())
	}
}

func TestRunFailsOpenWithoutEnoughSources(t *testing.T) {
	dir := t.TempDir()
	direct := filepath.Join(dir, "direct4.txt")
	if err := os.WriteFile(direct, []byte("1.1.1.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := Run(Config{
		Direct4Path: direct,
		Sources: []Source{
			{Name: "missing-a", Path: filepath.Join(dir, "nope-a.ipdb"), Kind: "ipdb"},
			{Name: "missing-b", Path: filepath.Join(dir, "nope-b.mmdb"), Kind: "mmdb"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.FailOpen == "" {
		t.Fatal("可用源为 0 时必须 fail-open 并说明原因")
	}
	if len(report.Disputed) != 0 || len(report.Promoted) != 0 {
		t.Fatalf("fail-open 时不得产出任何否决或晋级: %d/%d",
			len(report.Disputed), len(report.Promoted))
	}
	if len(report.Unavailable) != 2 {
		t.Fatalf("不可用的源必须逐个报出来: %v", report.Unavailable)
	}
}
