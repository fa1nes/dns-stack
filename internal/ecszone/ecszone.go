package ecszone

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"

	"github.com/dns-stack/dns-stack/internal/geoip"
	"github.com/dns-stack/dns-stack/internal/ipset"
)

var carrierNames = []struct{ keyword, name string }{
	{"电信", "电信"},
	{"联通", "联通"},
	{"网通", "联通"},
	{"移动", "移动"},
	{"铁通", "移动"},
	{"教育网", "教育网"},
	{"教育", "教育网"},
	{"广电", "广电"},
	{"有线", "广电"},
	{"鹏博士", "鹏博士"},
	{"长城", "长城宽带"},
}

var provinces = []string{
	"北京", "天津", "河北", "山西", "内蒙古",
	"辽宁", "吉林", "黑龙江", "上海", "江苏",
	"浙江", "安徽", "福建", "江西", "山东",
	"河南", "湖北", "湖南", "广东", "广西",
	"海南", "重庆", "四川", "贵州", "云南",
	"西藏", "陕西", "甘肃", "青海", "宁夏",
	"新疆",
}

var regionTrim = strings.NewReplacer("市", "", "省", "")

func ZoneOf(record map[string]string) string {
	region := regionTrim.Replace(record["region_name"])
	if region == "" {
		return ""
	}
	province := ""
	for _, name := range provinces {
		if strings.HasPrefix(region, name) {
			province = name
			break
		}
	}
	if province == "" {
		return ""
	}
	text := record["isp_domain"] + "|" + record["owner_domain"]
	for _, carrier := range carrierNames {
		if strings.Contains(text, carrier.keyword) {
			return province + carrier.name
		}
	}
	return ""
}

type Row struct {
	Lo, Hi uint32
	Zone   string
}

func LoadDirectIntervals(path string) ([]ipset.Range, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ranges []ipset.Range
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		masked := prefix.Masked()
		r, ok := ipset.PrefixRange(masked)
		if !ok {
			continue
		}
		ranges = append(ranges, globalParts(r)...)
	}
	return ipset.Collapse(ranges), nil
}

func globalParts(r ipset.Range) []ipset.Range {
	parts := []ipset.Range{r}
	for _, excluded := range nonGlobal {
		var next []ipset.Range
		for _, part := range parts {
			if excluded.Hi < part.Lo || excluded.Lo > part.Hi {
				next = append(next, part)
				continue
			}
			if excluded.Lo > part.Lo {
				next = append(next, ipset.Range{Lo: part.Lo, Hi: excluded.Lo - 1})
			}
			if excluded.Hi < part.Hi {
				next = append(next, ipset.Range{Lo: excluded.Hi + 1, Hi: part.Hi})
			}
		}
		parts = next
		if len(parts) == 0 {
			break
		}
	}
	return parts
}

var nonGlobal = buildNonGlobal()

func buildNonGlobal() []ipset.Range {
	values := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
		"192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4",
	}
	out := make([]ipset.Range, 0, len(values))
	for _, value := range values {
		if r, ok := ipset.PrefixRange(netip.MustParsePrefix(value)); ok {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Lo < out[j].Lo })
	return out
}

func intersections(lo, hi uint32, intervals []ipset.Range) []ipset.Range {
	if lo > hi || len(intervals) == 0 {
		return nil
	}
	index := sort.Search(len(intervals), func(i int) bool { return intervals[i].Lo > hi }) - 1
	var hits []ipset.Range
	for index >= 0 && intervals[index].Hi >= lo {
		start, end := intervals[index].Lo, intervals[index].Hi
		if start <= hi && end >= lo {
			hits = append(hits, ipset.Range{Lo: max32(lo, start), Hi: min32(hi, end)})
		}
		index--
	}
	for i, j := 0, len(hits)-1; i < j; i, j = i+1, j-1 {
		hits[i], hits[j] = hits[j], hits[i]
	}
	return hits
}

func max32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func min32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func MergeRows(rows []Row) ([]Row, int) {
	sorted := make([]Row, len(rows))
	copy(sorted, rows)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Lo != sorted[j].Lo {
			return sorted[i].Lo < sorted[j].Lo
		}
		if sorted[i].Hi != sorted[j].Hi {
			return sorted[i].Hi < sorted[j].Hi
		}
		return sorted[i].Zone < sorted[j].Zone
	})
	merged := make([]Row, 0, len(sorted))
	clipped := 0
	for _, row := range sorted {
		if row.Lo > row.Hi {
			continue
		}
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			if row.Zone == last.Zone && row.Lo <= last.Hi+1 {
				if row.Hi > last.Hi {
					last.Hi = row.Hi
				}
				continue
			}
			if row.Lo <= last.Hi {
				clipped++
				row.Lo = last.Hi + 1
				if row.Lo > row.Hi {
					continue
				}
			}
		}
		merged = append(merged, row)
	}
	return merged, clipped
}

func DirectCoverage(rows []Row, direct []ipset.Range) (uint64, uint64) {
	var total uint64
	for _, r := range direct {
		total += uint64(r.Hi-r.Lo) + 1
	}
	if total == 0 || len(rows) == 0 {
		return 0, total
	}
	var covered uint64
	for _, r := range direct {
		index := sort.Search(len(rows), func(i int) bool { return rows[i].Lo > r.Hi }) - 1
		for index >= 0 && rows[index].Hi >= r.Lo {
			row := rows[index]
			if row.Lo <= r.Hi && row.Hi >= r.Lo {
				covered += uint64(min32(r.Hi, row.Hi)-max32(r.Lo, row.Lo)) + 1
			}
			index--
		}
	}
	return covered, total
}

type BuildOptions struct {
	DBPath   string
	Direct   []ipset.Range
	Disputed *ipset.Set
}

type BuildStats struct {
	Raw            int
	SkippedNoZone  int
	DisputedSpans  int
	DisputedCutSum uint64
}

func anyOverlap(parts, cuts []ipset.Range) bool {
	for _, part := range parts {
		i := sort.Search(len(cuts), func(i int) bool { return cuts[i].Hi >= part.Lo })
		if i < len(cuts) && cuts[i].Lo <= part.Hi {
			return true
		}
	}
	return false
}

func Build(opt BuildOptions) ([]Row, BuildStats, error) {
	var rows []Row
	var stats BuildStats
	reader, err := geoip.OpenIPDB(opt.DBPath)
	if err != nil {
		return nil, stats, err
	}
	defer reader.Close()
	var cuts []ipset.Range
	if opt.Disputed != nil {
		cuts = opt.Disputed.Ranges()
	}
	err = reader.WalkV4(func(prefix netip.Prefix, record map[string]string) error {
		if record["country_code"] != "CN" {
			return nil
		}
		if !prefix.Addr().Is4() {
			return nil
		}
		zone := ZoneOf(record)
		if zone == "" {
			stats.SkippedNoZone++
			return nil
		}
		span, ok := ipset.PrefixRange(prefix.Masked())
		if !ok {
			return nil
		}
		parts := intersections(span.Lo, span.Hi, opt.Direct)
		if len(cuts) > 0 && anyOverlap(parts, cuts) {
			var before uint64
			for _, part := range parts {
				before += uint64(part.Hi-part.Lo) + 1
			}
			parts = ipset.Subtract(parts, cuts)
			var after uint64
			for _, part := range parts {
				after += uint64(part.Hi-part.Lo) + 1
			}
			if after < before {
				stats.DisputedSpans++
				stats.DisputedCutSum += before - after
			}
		}
		for _, part := range parts {
			rows = append(rows, Row{Lo: part.Lo, Hi: part.Hi, Zone: zone})
			stats.Raw++
		}
		return nil
	})
	if err != nil {
		return nil, stats, err
	}
	return rows, stats, nil
}

func FormatAddr(value uint32) string {
	return netip.AddrFrom4([4]byte{
		byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value),
	}).String()
}

func Render(rows []Row) string {
	var b strings.Builder
	b.WriteString("# generated by dns-stack ecs-zone\n")
	b.WriteString("# format: start,end,zone\n")
	for _, row := range rows {
		fmt.Fprintf(&b, "%s,%s,%s\n", FormatAddr(row.Lo), FormatAddr(row.Hi), row.Zone)
	}
	return b.String()
}

func LoadRows(path string) ([]Row, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Row
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) != 3 {
			continue
		}
		lo, okLo := parseAddr(fields[0])
		hi, okHi := parseAddr(fields[1])
		if !okLo || !okHi || lo > hi {
			continue
		}
		out = append(out, Row{Lo: lo, Hi: hi, Zone: strings.TrimSpace(fields[2])})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Lo < out[j].Lo })
	return out, nil
}

func parseAddr(text string) (uint32, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(text))
	if err != nil || !addr.Is4() {
		return 0, false
	}
	raw := addr.As4()
	return uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3]), true
}

func Marked(rows []Row, value uint32) bool {
	index := sort.Search(len(rows), func(i int) bool { return rows[i].Lo > value }) - 1
	return index >= 0 && rows[index].Hi >= value
}

func FirstOverlap(rows []Row) (int, bool) {
	for i := 0; i+1 < len(rows); i++ {
		if rows[i].Hi >= rows[i+1].Lo {
			return i, true
		}
	}
	return 0, false
}

func CountDataLines(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "#") {
			n++
		}
	}
	return n
}
