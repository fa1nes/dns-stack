package chnroute

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/dns-stack/dns-stack/internal/geoip"
	"github.com/dns-stack/dns-stack/internal/ipset"
)

var reserved = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
}

var offshoreProbes = []string{"23.56.25.51", "1.36.0.1", "119.31.191.80", "203.198.0.1"}

var mainlandProbes = []string{
	"223.6.6.6", "119.29.29.29", "1.2.4.8", "180.76.76.76", "223.5.5.5", "101.6.6.6",
}

type Options struct {
	APNICPath     string
	CNIPPath      string
	OutPath       string
	ExcludedPath  string
	StatsPath     string
	ReverseExlude bool
	MaxDropRatio  float64
	Out           io.Writer
}

type Result struct {
	Networks     int
	CNAddresses  uint64
	Supplemented int
	Excluded     int
	DroppedAddrs uint64
}

func infof(w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, "[信息] "+format+"\n", args...)
}

func warnf(w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, "[警告] "+format+"\n", args...)
}

func parseAPNIC(path string) ([]ipset.Range, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []ipset.Range
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		parts := strings.Split(strings.TrimSpace(sc.Text()), "|")
		if len(parts) < 7 || parts[1] != "CN" || parts[2] != "ipv4" {
			continue
		}
		if parts[6] != "allocated" && parts[6] != "assigned" {
			continue
		}
		start, err := netip.ParseAddr(parts[3])
		if err != nil || !start.Is4() {
			continue
		}
		count, err := strconv.ParseUint(parts[4], 10, 32)
		if err != nil || count == 0 {
			continue
		}
		lo := addrToUint(start)
		if uint64(lo)+count-1 > 0xffffffff {
			continue
		}
		out = append(out, ipset.Range{Lo: lo, Hi: lo + uint32(count) - 1})
	}
	return out, sc.Err()
}

func addrToUint(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

type foreignSpan struct {
	lo, hi uint32
	code   string
	name   string
}

func guardOffshoreLeak(cnipCN []ipset.Range) error {
	supp := ipset.New(cnipCN)
	for _, probe := range offshoreProbes {
		if containsAddr(supp, probe) {
			return fmt.Errorf(
				"港澳台地址 %s 落进了大陆补充集合，qqwry 的 country_code 语义可能已变更，中止以免污染直连判定", probe)
		}
	}
	return nil
}

type exclusion struct {
	kept     *ipset.Set
	dropped  []foreignSpan
	addrs    uint64
	ratio    float64
	rejected string
}

func planReverseExclusion(cnSet *ipset.Set, foreign []foreignSpan, maxDropRatio float64) exclusion {
	var overlapping []ipset.Range
	for _, f := range foreign {
		if cnSet.Overlaps(f.lo, f.hi) {
			overlapping = append(overlapping, ipset.Range{Lo: f.lo, Hi: f.hi})
		}
	}
	keptRanges := ipset.Subtract(cnSet.Ranges(), overlapping)
	keptSet := ipset.New(keptRanges)
	droppedRanges := ipset.Subtract(cnSet.Ranges(), keptRanges)

	plan := exclusion{kept: keptSet, addrs: totalAddresses(droppedRanges)}
	if before := cnSet.AddressCount(); before > 0 {
		plan.ratio = float64(plan.addrs) * 100 / float64(before)
	}
	if plan.ratio > maxDropRatio {
		plan.rejected = fmt.Sprintf(
			"反向排除命中 %.2f%% 的地址，超过 %.0f%% 上限，本轮不排除（qqwry 数据可能异常）",
			plan.ratio, maxDropRatio)
		return plan
	}
	var missing []string
	for _, probe := range mainlandProbes {
		if !containsAddr(keptSet, probe) {
			missing = append(missing, probe)
		}
	}
	if len(missing) > 0 {
		plan.rejected = fmt.Sprintf("反向排除会剔掉已知国内地址 %v，本轮不排除", missing)
		return plan
	}
	plan.dropped = attributeDropped(droppedRanges, foreign)
	return plan
}

func loadCNIP(path string) (cn []ipset.Range, foreign []foreignSpan, err error) {
	reader, err := geoip.OpenIPDB(path)
	if err != nil {
		return nil, nil, err
	}
	defer reader.Close()
	err = reader.WalkV4(func(prefix netip.Prefix, record map[string]string) error {
		span, ok := ipset.PrefixRange(prefix.Masked())
		if !ok {
			return nil
		}
		code := record["country_code"]
		if code == "CN" {
			cn = append(cn, span)
			return nil
		}
		if code == "" {
			return nil
		}
		name := record["country_name"]
		if name == "" {
			name = "?"
		}
		foreign = append(foreign, foreignSpan{lo: span.Lo, hi: span.Hi, code: code, name: name})
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return cn, foreign, nil
}

func containsAddr(set *ipset.Set, probe string) bool {
	addr, err := netip.ParseAddr(probe)
	if err != nil {
		return false
	}
	return set.Contains(addr)
}

func totalAddresses(ranges []ipset.Range) uint64 {
	var sum uint64
	for _, r := range ranges {
		sum += uint64(r.Hi-r.Lo) + 1
	}
	return sum
}

func Run(opt Options) (Result, error) {
	if opt.Out == nil {
		opt.Out = os.Stdout
	}
	if opt.MaxDropRatio == 0 {
		opt.MaxDropRatio = 5
	}
	var res Result

	cnRanges, err := parseAPNIC(opt.APNICPath)
	if err != nil {
		return res, err
	}
	if len(cnRanges) == 0 {
		return res, fmt.Errorf("APNIC 记录里没有可用的 CN IPv4 段")
	}

	var cnipCN []ipset.Range
	var foreign []foreignSpan
	if opt.CNIPPath != "" {
		cnipCN, foreign, err = loadCNIP(opt.CNIPPath)
		if err != nil {
			warnf(opt.Out, "qqwry 补充失败，仅用 APNIC：%v", err)
			cnipCN, foreign = nil, nil
		}
	}

	if len(cnipCN) > 0 {
		if err := guardOffshoreLeak(cnipCN); err != nil {
			return res, err
		}
		before := len(ipset.New(cnRanges).Ranges())
		cnRanges = append(cnRanges, cnipCN...)
		after := len(ipset.New(cnRanges).Ranges())
		res.Supplemented = len(ipset.New(cnipCN).Ranges())
		infof(opt.Out, "qqwry 补充 %d 条大陆段，合并后 %d -> %d 条", res.Supplemented, before, after)
	}

	cnSet := ipset.New(cnRanges)

	var excluded []foreignSpan
	if opt.ReverseExlude && len(foreign) > 0 {
		plan := planReverseExclusion(cnSet, foreign, opt.MaxDropRatio)
		if plan.rejected != "" {
			warnf(opt.Out, "%s", plan.rejected)
		} else {
			cnSet = plan.kept
			res.DroppedAddrs = plan.addrs
			excluded = plan.dropped
			res.Excluded = len(excluded)
			byCountry := map[string]int{}
			for _, e := range excluded {
				byCountry[e.code+"/"+e.name]++
			}
			infof(opt.Out, "反向排除 %d 段 / %s 个地址（%.2f%%）：%s",
				len(excluded), groupDigits(plan.addrs), plan.ratio, topCountries(byCountry, 5))
		}
	}

	if len(excluded) > 0 && opt.ExcludedPath != "" {
		if err := writeExcluded(opt.ExcludedPath, excluded); err != nil {
			warnf(opt.Out, "排除清单写入失败：%v", err)
		}
	}

	res.CNAddresses = cnSet.AddressCount()

	all := append([]ipset.Range{}, cnSet.Ranges()...)
	for _, value := range reserved {
		if r, ok := ipset.PrefixRange(netip.MustParsePrefix(value)); ok {
			all = append(all, r)
		}
	}
	prefixes := ipset.New(all).Prefixes()
	res.Networks = len(prefixes)

	var body strings.Builder
	for _, p := range prefixes {
		body.WriteString(p.String())
		body.WriteString("\n")
	}
	if err := os.WriteFile(opt.OutPath, []byte(body.String()), 0o644); err != nil {
		return res, err
	}

	if opt.StatsPath != "" {
		stats := fmt.Sprintf("NETWORKS=%d\nCN_ADDRESSES=%d\n", res.Networks, res.CNAddresses)
		if err := os.WriteFile(opt.StatsPath, []byte(stats), 0o644); err != nil {
			return res, err
		}
	}

	infof(opt.Out, "汇总后网段：%d 条（含 %d 条保留网段）", res.Networks, len(reserved))
	infof(opt.Out, "大陆覆盖地址：%s 个", groupDigits(res.CNAddresses))
	return res, nil
}

func attributeDropped(dropped []ipset.Range, foreign []foreignSpan) []foreignSpan {
	sorted := append([]foreignSpan(nil), foreign...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].lo < sorted[j].lo })
	starts := make([]uint32, len(sorted))
	for i, f := range sorted {
		starts[i] = f.lo
	}
	var out []foreignSpan
	for _, r := range dropped {
		for _, prefix := range ipset.RangePrefixes(r) {
			span, ok := ipset.PrefixRange(prefix)
			if !ok {
				continue
			}
			code, name := "?", "?"
			i := sort.Search(len(starts), func(i int) bool { return starts[i] > span.Lo }) - 1
			if i >= 0 && sorted[i].hi >= span.Lo {
				code, name = sorted[i].code, sorted[i].name
			}
			out = append(out, foreignSpan{lo: span.Lo, hi: span.Hi, code: code, name: name})
		}
	}
	return out
}

func writeExcluded(path string, excluded []foreignSpan) error {
	sorted := append([]foreignSpan(nil), excluded...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].lo < sorted[j].lo })
	var b strings.Builder
	b.WriteString("# APNIC 判 CN 但 qqwry 判境外，已从直连集合排除\n")
	b.WriteString("# 网段 国别码 国别名\n")
	for _, e := range sorted {
		for _, p := range ipset.RangePrefixes(ipset.Range{Lo: e.lo, Hi: e.hi}) {
			fmt.Fprintf(&b, "%s %s %s\n", p, e.code, e.name)
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func topCountries(counts map[string]int, limit int) string {
	type pair struct {
		key string
		n   int
	}
	list := make([]pair, 0, len(counts))
	for key, n := range counts {
		list = append(list, pair{key, n})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].key < list[j].key
	})
	parts := make([]string, 0, limit)
	for i, item := range list {
		if i >= limit {
			break
		}
		parts = append(parts, fmt.Sprintf("%s %d段", item.key, item.n))
	}
	return strings.Join(parts, "、")
}

func groupDigits(value uint64) string {
	text := strconv.FormatUint(value, 10)
	if len(text) <= 3 {
		return text
	}
	var b strings.Builder
	lead := len(text) % 3
	if lead > 0 {
		b.WriteString(text[:lead])
	}
	for i := lead; i < len(text); i += 3 {
		if b.Len() > 0 {
			b.WriteString(",")
		}
		b.WriteString(text[i : i+3])
	}
	return b.String()
}
