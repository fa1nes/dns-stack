package geoaudit

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/geoip"
	"github.com/dns-stack/dns-stack/internal/ipset"
)

const (
	MinSources          = 2
	DefaultDisputeNeed  = 2
	DefaultPromoteLimit = 1 << 22
	DefaultDisputeRatio = 5
	KindDisputed        = "disputed"
	KindPromoted        = "promoted"
)

type Source struct {
	Name string
	Path string
	Kind string
}

type Span struct {
	Lo, Hi  uint32
	Country string
	Source  string
}

type Report struct {
	Entries          int
	TotalAddresses   uint64
	Sources          []string
	Unavailable      map[string]string
	OffshoreBySource map[string]uint64
	MainlandBySource map[string]uint64
	DisputeNeed      int
	PromoteNeed      int
	Disputed         []Span
	DisputedTotal    uint64
	Promoted         []Span
	PromotedTotal    uint64
	FailOpen         string
	PromoteRejected  string
	DisputeRejected  string
}

type Config struct {
	Direct4Path  string
	Sources      []Source
	DisputeNeed  int
	PromoteLimit uint64
	DisputeLimit uint64
}

func DefaultSources(geoDir string) []Source {
	return []Source{
		{Name: "qqwry", Path: filepath.Join(geoDir, "qqwry.ipdb"), Kind: "ipdb"},
		{Name: "maxmind", Path: filepath.Join(geoDir, "GeoLite2-City.mmdb"), Kind: "mmdb"},
		{Name: "dbip", Path: filepath.Join(geoDir, "dbip-city.mmdb"), Kind: "mmdb"},
		{Name: "ipinfo", Path: filepath.Join(geoDir, "ipinfo-lite.mmdb"), Kind: "mmdb"},
	}
}

func loadDirect(path string) ([]ipset.Range, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	res, err := ipset.LoadReader(f, ipset.LoadOptions{GlobalOnly: true})
	if err != nil {
		return nil, err
	}
	return res.Set.Ranges(), nil
}

func rangesOverlap(a, b ipset.Range) (ipset.Range, bool) {
	lo, hi := a.Lo, a.Hi
	if b.Lo > lo {
		lo = b.Lo
	}
	if b.Hi < hi {
		hi = b.Hi
	}
	if lo > hi {
		return ipset.Range{}, false
	}
	return ipset.Range{Lo: lo, Hi: hi}, true
}

func intersect(dst []ipset.Range, span ipset.Range, direct []ipset.Range) []ipset.Range {
	dst = dst[:0]
	index := sort.Search(len(direct), func(i int) bool { return direct[i].Hi >= span.Lo })
	for ; index < len(direct) && direct[index].Lo <= span.Hi; index++ {
		if part, ok := rangesOverlap(span, direct[index]); ok {
			dst = append(dst, part)
		}
	}
	return dst
}

func subtractSorted(dst []ipset.Range, span ipset.Range, hits []ipset.Range) []ipset.Range {
	dst = dst[:0]
	cursor := span.Lo
	for _, hit := range hits {
		if hit.Lo > cursor {
			dst = append(dst, ipset.Range{Lo: cursor, Hi: hit.Lo - 1})
		}
		if hit.Hi == ^uint32(0) {
			return dst
		}
		if hit.Hi >= cursor {
			cursor = hit.Hi + 1
		}
	}
	if cursor <= span.Hi {
		dst = append(dst, ipset.Range{Lo: cursor, Hi: span.Hi})
	}
	return dst
}

type scanResult struct {
	offshore      []Span
	mainland      []Span
	offshoreTotal uint64
	mainlandTotal uint64

	hits []ipset.Range
	cuts []ipset.Range
}

func appendSpan(dst []Span, lo, hi uint32, code, name string) []Span {
	if n := len(dst); n > 0 {
		last := &dst[n-1]
		if last.Country == code && last.Hi != ^uint32(0) && last.Hi+1 == lo {
			last.Hi = hi
			return dst
		}
	}
	return append(dst, Span{Lo: lo, Hi: hi, Country: code, Source: name})
}

func (s *scanResult) add(name, code string, span ipset.Range, direct []ipset.Range) {
	if code == "CN" {
		s.hits = intersect(s.hits, span, direct)
		s.cuts = subtractSorted(s.cuts, span, s.hits)
		for _, outside := range s.cuts {
			for _, part := range ipset.GlobalParts(outside) {
				s.mainland = appendSpan(s.mainland, part.Lo, part.Hi, "CN", name)
				s.mainlandTotal += uint64(part.Hi-part.Lo) + 1
			}
		}
		return
	}
	s.hits = intersect(s.hits, span, direct)
	for _, inside := range s.hits {
		s.offshore = appendSpan(s.offshore, inside.Lo, inside.Hi, code, name)
		s.offshoreTotal += uint64(inside.Hi-inside.Lo) + 1
	}
}

func scan(src Source, direct []ipset.Range) (*scanResult, error) {
	out := &scanResult{}
	switch src.Kind {
	case "ipdb":
		reader, err := geoip.OpenIPDB(src.Path)
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		err = reader.WalkV4(func(prefix netip.Prefix, record map[string]string) error {
			code := strings.ToUpper(strings.TrimSpace(record["country_code"]))
			if code == "" {
				return nil
			}
			span, ok := ipset.PrefixRange(prefix.Masked())
			if !ok {
				return nil
			}
			out.add(src.Name, code, span, direct)
			return nil
		})
		if err != nil {
			return nil, err
		}
	case "mmdb":
		reader, err := geoip.OpenMMDB(src.Path)
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		err = reader.WalkV4(func(prefix netip.Prefix, rawCode string) error {
			code := strings.ToUpper(strings.TrimSpace(rawCode))
			if code == "" {
				return nil
			}
			span, ok := ipset.PrefixRange(prefix.Masked())
			if !ok {
				return nil
			}
			out.add(src.Name, code, span, direct)
			return nil
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("未知的归属库类型: %s", src.Kind)
	}
	return out, nil
}

func mergeAgreement(sets [][]Span, need int) ([]Span, uint64) {
	if need < 1 {
		return nil, 0
	}
	type edge struct {
		at    uint32
		delta int
		code  string
	}
	var edges []edge
	for _, spans := range sets {
		for _, s := range spans {
			edges = append(edges, edge{s.Lo, 1, s.Country})
			if s.Hi == ^uint32(0) {
				continue
			}
			edges = append(edges, edge{s.Hi + 1, -1, s.Country})
		}
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].at != edges[j].at {
			return edges[i].at < edges[j].at
		}
		return edges[i].delta < edges[j].delta
	})
	var out []Span
	var total uint64
	depth := 0
	var start uint32
	code := ""
	for i := 0; i < len(edges); i++ {
		previous := depth
		at := edges[i].at
		for i < len(edges) && edges[i].at == at {
			depth += edges[i].delta
			if edges[i].delta > 0 && code == "" {
				code = edges[i].code
			}
			i++
		}
		i--
		if previous < need && depth >= need {
			start = at
		} else if previous >= need && depth < need {
			if at > start {
				out = append(out, Span{Lo: start, Hi: at - 1, Country: code, Source: "agreed"})
				total += uint64(at - start)
			}
			code = ""
		}
	}
	return out, total
}

func Run(cfg Config) (Report, error) {
	direct, err := loadDirect(cfg.Direct4Path)
	if err != nil {
		return Report{}, err
	}
	report := Report{
		Entries:          len(direct),
		Unavailable:      map[string]string{},
		OffshoreBySource: map[string]uint64{},
		MainlandBySource: map[string]uint64{},
	}
	for _, r := range direct {
		report.TotalAddresses += uint64(r.Hi-r.Lo) + 1
	}
	if report.TotalAddresses == 0 {
		return report, fmt.Errorf("direct4 为空，无从审计")
	}

	var offshoreSets, mainlandSets [][]Span
	for _, src := range cfg.Sources {
		if strings.TrimSpace(src.Path) == "" {
			continue
		}
		result, err := scan(src, direct)
		if err != nil {
			report.Unavailable[src.Name] = err.Error()
			continue
		}
		report.Sources = append(report.Sources, src.Name)
		report.OffshoreBySource[src.Name] = result.offshoreTotal
		report.MainlandBySource[src.Name] = result.mainlandTotal
		offshoreSets = append(offshoreSets, result.offshore)
		mainlandSets = append(mainlandSets, result.mainland)
	}

	if len(report.Sources) < MinSources {
		report.FailOpen = fmt.Sprintf(
			"可用归属库只有 %d 个（至少 %d 个才能交叉验证），本轮不否决也不晋级任何地址",
			len(report.Sources), MinSources)
		return report, nil
	}

	need := cfg.DisputeNeed
	if need <= 0 {
		need = DefaultDisputeNeed
	}
	if need > len(report.Sources) {
		need = len(report.Sources)
	}
	report.DisputeNeed = need
	disputed, disputedTotal := mergeAgreement(offshoreSets, need)
	disputeLimit := cfg.DisputeLimit
	if disputeLimit == 0 {
		disputeLimit = report.TotalAddresses * DefaultDisputeRatio / 100
	}
	if disputedTotal > disputeLimit {
		report.DisputeRejected = fmt.Sprintf(
			"争议候选 %d 个地址超过上限 %d（direct4 的 %d%%），本轮整体不否决（多半是某个归属库的国家码整体漂移）",
			disputedTotal, disputeLimit, DefaultDisputeRatio)
	} else {
		report.Disputed, report.DisputedTotal = disputed, disputedTotal
	}

	report.PromoteNeed = len(report.Sources)
	promoted, promotedTotal := mergeAgreement(mainlandSets, report.PromoteNeed)
	limit := cfg.PromoteLimit
	if limit == 0 {
		limit = DefaultPromoteLimit
	}
	if promotedTotal > limit {
		report.PromoteRejected = fmt.Sprintf(
			"晋级候选 %d 个地址超过上限 %d，本轮整体不晋级（多半是某个归属库的 CN 段整体漂移）",
			promotedTotal, limit)
	} else {
		report.Promoted, report.PromotedTotal = promoted, promotedTotal
	}
	return report, nil
}

func Render(kind string, need int, sources []string, spans []Span) string {
	ranges := make([]ipset.Range, 0, len(spans))
	for _, span := range spans {
		ranges = append(ranges, ipset.Range{Lo: span.Lo, Hi: span.Hi})
	}
	set := ipset.New(ranges)
	prefixes := set.Prefixes()
	var b strings.Builder
	fmt.Fprintf(&b, "# generated-at %d\n", time.Now().Unix())
	fmt.Fprintf(&b, "# kind %s\n", kind)
	fmt.Fprintf(&b, "# agreement %d\n", need)
	fmt.Fprintf(&b, "# sources %s\n", strings.Join(sources, ","))
	fmt.Fprintf(&b, "# addresses %d\n", set.AddressCount())
	fmt.Fprintf(&b, "# prefixes %d\n", len(prefixes))
	for _, p := range prefixes {
		b.WriteString(p.String())
		b.WriteString("\n")
	}
	return b.String()
}

func Write(path, kind string, need int, sources []string, spans []Span) error {
	temp := path + ".tmp"
	if err := os.WriteFile(temp, []byte(Render(kind, need, sources, spans)), 0o644); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		os.Remove(temp)
		return err
	}
	return nil
}

type Snapshot struct {
	Set         *ipset.Set
	Kind        string
	Agreement   int
	Sources     []string
	GeneratedAt int64
	Prefixes    int
}

func (s Snapshot) Age(now time.Time) time.Duration {
	if s.GeneratedAt == 0 {
		return 0
	}
	return now.Sub(time.Unix(s.GeneratedAt, 0))
}

func LoadSnapshot(path string) (Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return Snapshot{}, err
	}
	defer f.Close()

	var meta []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var body strings.Builder
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			meta = append(meta, strings.TrimSpace(line))
			continue
		}
		body.WriteString(line)
		body.WriteString("\n")
	}
	if err := sc.Err(); err != nil {
		return Snapshot{}, err
	}
	res, err := ipset.LoadReader(strings.NewReader(body.String()), ipset.LoadOptions{GlobalOnly: true})
	if err != nil {
		return Snapshot{}, err
	}
	out := Snapshot{Set: res.Set, Prefixes: res.Total}
	for _, line := range meta {
		fields := strings.Fields(strings.TrimPrefix(line, "#"))
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "generated-at":
			out.GeneratedAt, _ = strconv.ParseInt(fields[1], 10, 64)
		case "kind":
			out.Kind = fields[1]
		case "agreement":
			out.Agreement, _ = strconv.Atoi(fields[1])
		case "sources":
			out.Sources = strings.Split(fields[1], ",")
		}
	}
	return out, nil
}

func FormatAddr(value uint32) string {
	return netip.AddrFrom4([4]byte{
		byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value),
	}).String()
}
