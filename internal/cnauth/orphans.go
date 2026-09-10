package cnauth

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"time"

	"github.com/dns-stack/dns-stack/internal/ipset"
)

const DefaultMaxForeignOrphans = 9

type CountryLookup interface {
	CountryOf(addr netip.Addr) (code, label string, available bool)
}

type OrphanOptions struct {
	ECSConfPath        string
	Direct4Path        string
	CNAuthorityPath    string
	SharedExcludedPath string
	AccumStatePath     string
	AccumTTL           time.Duration
	MaxForeign         int
	Geo                CountryLookup
	Now                func() time.Time
	Out                io.Writer
	ListAll            bool
}

type OrphanEntry struct {
	Prefix  netip.Prefix `json:"prefix"`
	Code    string       `json:"country_code"`
	Label   string       `json:"label"`
	Foreign bool         `json:"foreign"`
}

type OrphanReport struct {
	Whitelist      int            `json:"whitelist"`
	Direct4        int            `json:"direct4"`
	CNAuthority    int            `json:"cn_authority"`
	SharedExcluded int            `json:"shared_excluded"`
	AccumRetained  int            `json:"accum_retained"`
	AccumNote      string         `json:"accum_note"`
	Orphans        []OrphanEntry  `json:"orphans"`
	ForeignOrphans int            `json:"foreign_orphans"`
	MaxForeign     int            `json:"max_foreign"`
	ByCode         map[string]int `json:"by_code"`
	OK             bool           `json:"ok"`
}

func LoadECSWhitelist(path string) ([]netip.Prefix, error) {
	lines, err := loadLines(path)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, line := range lines {
		m := ecsLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		prefix, err := netip.ParsePrefix(m[1])
		if err != nil {
			return nil, fmt.Errorf("ECS 白名单行格式错误: %s", line)
		}
		out = append(out, prefix.Masked())
	}
	return out, nil
}

func loadPrefixFile(path string) ([]netip.Prefix, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	loaded, err := ipset.LoadReader(f, ipset.LoadOptions{})
	if err != nil {
		return nil, err
	}
	return loaded.Set.Prefixes(), nil
}

func liveAccumPrefixes(path string, ttl time.Duration, now time.Time) ([]netip.Prefix, string) {
	since, ok := loadAccumState(path)
	if !ok {
		return nil, "累积状态文件不可读，全部按真孤儿处理（fail-closed）"
	}
	if len(since) == 0 {
		return nil, "累积状态为空（首次运行？），全部按真孤儿处理"
	}
	var out []netip.Prefix
	expired := 0
	nowTS := now.Unix()
	for key, stamp := range since {
		prefix, err := netip.ParsePrefix(key)
		if err != nil || !prefix.Addr().Is4() {
			continue
		}
		if nowTS-stamp > int64(ttl.Seconds()) {
			expired++
			continue
		}
		out = append(out, prefix.Masked())
	}
	note := fmt.Sprintf("TTL 内累积保留 %d 条", len(out))
	if expired > 0 {
		note += fmt.Sprintf("（另有 %d 条已过 TTL，等下轮清理）", expired)
	}
	return out, note
}

func AuditOrphans(opt OrphanOptions) (OrphanReport, error) {
	now := time.Now
	if opt.Now != nil {
		now = opt.Now
	}
	if opt.AccumTTL <= 0 {
		opt.AccumTTL = DefaultAccumTTL
	}
	if opt.MaxForeign < 0 {
		return OrphanReport{}, fmt.Errorf("境外孤儿阈值不能为负数")
	}

	report := OrphanReport{MaxForeign: opt.MaxForeign, ByCode: map[string]int{}}
	whitelist, err := LoadECSWhitelist(opt.ECSConfPath)
	if err != nil {
		return report, fmt.Errorf("读不到或无法解析 ECS 白名单（这不代表没有孤儿，代表判断不了）: %w", err)
	}
	if len(whitelist) == 0 {
		return report, fmt.Errorf("ECS 白名单为空或格式不符: %s", opt.ECSConfPath)
	}
	direct4, err := loadPrefixFile(opt.Direct4Path)
	if err != nil {
		return report, fmt.Errorf("读不到 direct4: %w", err)
	}
	if len(direct4) == 0 {
		return report, fmt.Errorf("direct4 为空: %s", opt.Direct4Path)
	}
	cnAuthority, err := loadPrefixFile(opt.CNAuthorityPath)
	if err != nil {
		return report, fmt.Errorf("读不到 cn-authority: %w", err)
	}
	shared, err := loadPrefixFile(opt.SharedExcludedPath)
	if err != nil && !os.IsNotExist(err) {
		return report, fmt.Errorf("读不到共享排除清单: %w", err)
	}

	report.Whitelist = len(whitelist)
	report.Direct4 = len(direct4)
	report.CNAuthority = len(cnAuthority)
	report.SharedExcluded = len(shared)

	accum, note := liveAccumPrefixes(opt.AccumStatePath, opt.AccumTTL, now())
	report.AccumNote = note

	legitimate := setOf(append(append(append([]netip.Prefix{}, direct4...), cnAuthority...), shared...))
	retained := setOf(accum)

	var orphans []netip.Prefix
	for _, prefix := range whitelist {
		if legitimate.CoversPrefix(prefix) {
			continue
		}
		if retained.CoversPrefix(prefix) {
			report.AccumRetained++
			continue
		}
		orphans = append(orphans, prefix)
	}
	sortPrefixes(orphans)

	if len(orphans) == 0 {
		report.OK = true
		return report, nil
	}
	if opt.Geo == nil {
		return report, fmt.Errorf("找不到归属库，无法判断 %d 条孤儿的归属", len(orphans))
	}

	unavailable := 0
	for _, prefix := range orphans {
		code, label, available := opt.Geo.CountryOf(prefix.Addr())
		if !available {
			unavailable++
		}
		if code == "" {
			code = "??"
		}
		report.ByCode[code]++
		report.Orphans = append(report.Orphans, OrphanEntry{
			Prefix: prefix, Code: code, Label: label, Foreign: code != "CN",
		})
		if code != "CN" {
			report.ForeignOrphans++
		}
	}
	if unavailable == len(orphans) {
		return report, fmt.Errorf("归属库整体不可用（%d 条孤儿全部查不到归属）", len(orphans))
	}
	report.OK = report.ForeignOrphans <= opt.MaxForeign
	return report, nil
}

func setOf(prefixes []netip.Prefix) *ipset.Set {
	ranges := make([]ipset.Range, 0, len(prefixes))
	for _, prefix := range prefixes {
		if r, ok := ipset.PrefixRange(prefix); ok {
			ranges = append(ranges, r)
		}
	}
	return ipset.New(ranges)
}

func sortPrefixes(prefixes []netip.Prefix) {
	sort.Slice(prefixes, func(i, j int) bool {
		a, b := prefixes[i], prefixes[j]
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
}

func (r OrphanReport) Write(out io.Writer, listAll bool) {
	fmt.Fprintf(out, "白名单条目        %d\n", r.Whitelist)
	fmt.Fprintf(out, "  ├ direct4         %d\n", r.Direct4)
	fmt.Fprintf(out, "  ├ cn-authority    %d\n", r.CNAuthority)
	fmt.Fprintf(out, "  ├ shared-excluded %d\n", r.SharedExcluded)
	fmt.Fprintf(out, "  ├ 累积保留        %d  (%s)\n", r.AccumRetained, r.AccumNote)
	ratio := 0.0
	if r.Whitelist > 0 {
		ratio = float64(len(r.Orphans)) * 100 / float64(r.Whitelist)
	}
	fmt.Fprintf(out, "  └ 孤儿            %d  (%.2f%%)\n", len(r.Orphans), ratio)
	if len(r.Orphans) == 0 {
		fmt.Fprintln(out, "\n[成功] 无孤儿条目。")
		return
	}

	codes := make([]string, 0, len(r.ByCode))
	for code := range r.ByCode {
		codes = append(codes, code)
	}
	sort.Slice(codes, func(i, j int) bool {
		if r.ByCode[codes[i]] != r.ByCode[codes[j]] {
			return r.ByCode[codes[i]] > r.ByCode[codes[j]]
		}
		return codes[i] < codes[j]
	})
	fmt.Fprint(out, "\n国别分布  ")
	for i, code := range codes {
		if i > 0 {
			fmt.Fprint(out, ", ")
		}
		fmt.Fprintf(out, "%s=%d", code, r.ByCode[code])
	}
	fmt.Fprintf(out, "\n境外孤儿  %d / %d\n", r.ForeignOrphans, len(r.Orphans))

	shown := make([]OrphanEntry, 0, len(r.Orphans))
	for _, entry := range r.Orphans {
		if listAll || entry.Foreign {
			shown = append(shown, entry)
		}
	}
	limit := len(shown)
	if !listAll && limit > 40 {
		limit = 40
	}
	if limit > 0 {
		title := "境外孤儿"
		if listAll {
			title = "全部孤儿"
		}
		fmt.Fprintf(out, "\n%s（%d 条）：\n", title, limit)
		for _, entry := range shown[:limit] {
			fmt.Fprintf(out, "  %-20s %-6s %s\n", entry.Prefix, entry.Code, entry.Label)
		}
		if limit < len(shown) {
			fmt.Fprintf(out, "  … 另有 %d 条，用 --list 看全部\n", len(shown)-limit)
		}
	}
	if r.OK {
		fmt.Fprintf(out, "\n[成功] 境外孤儿 %d 条 ≤ 阈值 %d\n", r.ForeignOrphans, r.MaxForeign)
		return
	}
	fmt.Fprintf(out, "\n[失败] 境外孤儿 %d 条 > 阈值 %d，这些境外权威正在收到中国 ECS\n",
		r.ForeignOrphans, r.MaxForeign)
}
