package cnauth

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/domain"
	"github.com/dns-stack/dns-stack/internal/geoaudit"
	"github.com/dns-stack/dns-stack/internal/infra"
	"github.com/dns-stack/dns-stack/internal/ipset"
	"github.com/dns-stack/dns-stack/internal/ruleset"
)

const (
	DefaultAccumTTL      = 72 * time.Hour
	DefaultSharedMaxAge  = 6 * time.Hour
	DefaultCrossMaxAge   = 48 * time.Hour
	DefaultMaxECSEntries = 20000
)

type Options struct {
	Direct4Path       string
	PairsPath         string
	ManualPath        string
	SharedPath        string
	DisputedPath      string
	PromotedPath      string
	PSLPaths          []string
	ResultPath        string
	MatchedPath       string
	ECSOutPath        string
	PrevECSPath       string
	ECSStatePath      string
	SharedExcludedOut string
	Aggregate         int
	AccumTTL          time.Duration
	SharedMaxAge      time.Duration
	CrossMaxAge       time.Duration
	MaxECSEntries     int
	Now               func() time.Time
	Out               io.Writer
}

type Result struct {
	Zones          int
	MatchedZones   int
	ForcedZones    int
	DeadZones      int
	RoutePrefixes  int
	ECSPrefixes    int
	SharedExcluded int
	DisputedCut    int
	PromotedUsed   int
	AccumKept      int
	RTOSeen        bool
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

type printer struct{ w io.Writer }

func (p printer) infof(format string, args ...any) {
	fmt.Fprintf(p.w, "[信息] "+format+"\n", args...)
}

func (p printer) warnf(format string, args ...any) {
	fmt.Fprintf(p.w, "[警告] "+format+"\n", args...)
}

func loadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out, sc.Err()
}

func loadManual(path string) map[string]struct{} {
	out := map[string]struct{}{}
	lines, err := loadLines(path)
	if err != nil {
		return out
	}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		out[strings.ToLower(trimmed)] = struct{}{}
	}
	return out
}

type sharedList struct {
	addrs       map[netip.Addr]struct{}
	generatedAt int64
}

func loadShared(path string) sharedList {
	out := sharedList{addrs: map[netip.Addr]struct{}{}}
	lines, err := loadLines(path)
	if err != nil {
		return out
	}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# generated-at") {
			fields := strings.Fields(trimmed)
			if len(fields) >= 3 {
				if value, err := strconv.ParseInt(fields[2], 10, 64); err == nil {
					out.generatedAt = value
				}
			}
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if addr, err := netip.ParseAddr(strings.Fields(trimmed)[0]); err == nil {
			out.addrs[addr] = struct{}{}
		}
	}
	return out
}

func loadCross(p printer, path, wantKind string, maxAge time.Duration, now time.Time) (geoaudit.Snapshot, error) {
	snapshot, err := geoaudit.LoadSnapshot(path)
	if err != nil {
		p.warnf("读不到多源%s清单 %s：%v", wantKind, path, err)
		p.warnf("  本轮不做跨库交叉；检查 dns-stack-geo-cross.timer")
		return geoaudit.Snapshot{}, nil
	}
	if snapshot.Kind != "" && snapshot.Kind != wantKind {
		return geoaudit.Snapshot{}, fmt.Errorf(
			"%s 声明的 kind 是 %q，期望 %q，拒绝按错误的方向使用", path, snapshot.Kind, wantKind)
	}
	if snapshot.GeneratedAt != 0 {
		age := snapshot.Age(now)
		if age > maxAge {
			p.warnf("多源%s清单已 %d 小时未更新（阈值 %d 小时），仍按旧内容交叉",
				wantKind, int(age.Hours()), int(maxAge.Hours()))
		}
	}
	return snapshot, nil
}

func parsePairs(path string) (infra.Snapshot, map[string]map[string]struct{}, error) {
	lines, err := loadLines(path)
	if err != nil {
		return infra.Snapshot{}, nil, err
	}
	var snapshot infra.Snapshot
	zones := map[string]map[string]struct{}{}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		zone := fields[0]
		if zones[zone] == nil {
			zones[zone] = map[string]struct{}{}
		}
		zones[zone][fields[1]] = struct{}{}
		entry := infra.Entry{Zone: zone, IP: addr}
		if len(fields) >= 3 {
			if rto, err := strconv.Atoi(fields[2]); err == nil && rto >= 0 {
				entry.RTO = rto
				entry.HasRTO = true
			}
		}
		snapshot.Entries = append(snapshot.Entries, entry)
	}
	return snapshot, zones, nil
}

var ecsLine = regexp.MustCompile(`^\s*send-client-subnet:\s*(\S+)`)

func loadPrevECS(path string) map[netip.Prefix]struct{} {
	out := map[netip.Prefix]struct{}{}
	lines, err := loadLines(path)
	if err != nil {
		return out
	}
	for _, line := range lines {
		m := ecsLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		prefix, err := netip.ParsePrefix(m[1])
		if err != nil {
			continue
		}
		if prefix.Addr().Is4() && prefix.Bits() == 32 {
			out[prefix.Masked()] = struct{}{}
		}
	}
	return out
}

func loadAccumState(path string) (map[string]int64, bool) {
	out := map[string]int64{}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, true
		}
		return out, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		if value, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
			out[fields[0]] = value
		}
	}
	if err := sc.Err(); err != nil {
		return out, false
	}
	return out, true
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	temp := path + ".tmp"
	if err := os.WriteFile(temp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		os.Remove(temp)
		return err
	}
	return nil
}

func sortedSample(values map[string]struct{}, limit int) ([]string, int) {
	out := make([]string, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	sort.Strings(out)
	total := len(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, total
}

func joinSample(values map[string]struct{}, limit int) string {
	sample, total := sortedSample(values, limit)
	text := strings.Join(sample, ", ")
	if total > limit {
		text += fmt.Sprintf(" …等 %d 个", total)
	}
	return text
}

func Run(opt Options) (Result, error) {
	if opt.Out == nil {
		opt.Out = os.Stdout
	}
	p := printer{w: opt.Out}
	var res Result
	now := opt.now()

	if opt.AccumTTL == 0 {
		opt.AccumTTL = DefaultAccumTTL
	}
	if opt.SharedMaxAge == 0 {
		opt.SharedMaxAge = DefaultSharedMaxAge
	}
	if opt.CrossMaxAge == 0 {
		opt.CrossMaxAge = DefaultCrossMaxAge
	}
	if opt.MaxECSEntries == 0 {
		opt.MaxECSEntries = DefaultMaxECSEntries
	}

	shared := loadShared(opt.SharedPath)
	if shared.generatedAt != 0 {
		age := now.Sub(time.Unix(shared.generatedAt, 0))
		if age > opt.SharedMaxAge {
			p.warnf("共享 anycast 清单已 %d 小时未更新（阈值 %d 小时），新出现的多租户权威不会被排除",
				int(age.Hours()), int(opt.SharedMaxAge.Hours()))
			p.warnf("  检查: systemctl status dns-stack-shared-anycast.timer")
		}
	}

	psl, note := domain.LoadPSL(opt.PSLPaths)
	if psl == nil {
		return res, fmt.Errorf("缺少有效的 Public Suffix List，拒绝更新权威集合")
	}
	p.infof("%s", note)

	directFile, err := os.Open(opt.Direct4Path)
	if err != nil {
		return res, err
	}
	direct, err := ipset.LoadReader(directFile, ipset.LoadOptions{GlobalOnly: true})
	_ = directFile.Close()
	if err != nil {
		return res, err
	}
	if direct.Set == nil || direct.Set.Len() == 0 {
		return res, fmt.Errorf("direct4 中没有有效的全局 IPv4 网段，拒绝更新权威集合")
	}

	disputed, err := loadCross(p, opt.DisputedPath, geoaudit.KindDisputed, opt.CrossMaxAge, now)
	if err != nil {
		return res, err
	}
	promoted, err := loadCross(p, opt.PromotedPath, geoaudit.KindPromoted, opt.CrossMaxAge, now)
	if err != nil {
		return res, err
	}
	if disputed.Prefixes > 0 || promoted.Prefixes > 0 {
		p.infof("多源交叉：争议 %d 条前缀（agreement=%d，来源 %s），晋级 %d 条前缀（agreement=%d）",
			disputed.Prefixes, disputed.Agreement, strings.Join(disputed.Sources, ","),
			promoted.Prefixes, promoted.Agreement)
	} else {
		p.warnf("多源交叉清单为空或不可读，本轮判据与只信 APNIC 完全一致（fail-open）")
	}

	snapshot, zoneIPs, err := parsePairs(opt.PairsPath)
	if err != nil {
		return res, err
	}
	res.Zones = len(zoneIPs)

	built, err := ruleset.Build(snapshot, ruleset.Config{
		Direct:        direct.Set,
		Disputed:      disputed.Set,
		Promoted:      promoted.Set,
		PSL:           psl,
		ManualZones:   loadManual(opt.ManualPath),
		SharedAnycast: shared.addrs,
		Aggregate:     opt.Aggregate,
	})
	if err != nil {
		return res, err
	}
	res.RTOSeen = built.RTOSeen

	sharedSet := map[string]struct{}{}
	for _, ip := range built.SharedExcluded {
		sharedSet[ip] = struct{}{}
	}
	if opt.SharedExcludedOut != "" {
		var b strings.Builder
		for _, ip := range built.SharedExcluded {
			b.WriteString(ip)
			b.WriteString("\n")
		}
		if err := os.WriteFile(opt.SharedExcludedOut, []byte(b.String()), 0o644); err != nil {
			return res, err
		}
	}

	zonesOf := func(addresses []string) map[string]struct{} {
		want := map[string]struct{}{}
		for _, ip := range addresses {
			want[ip] = struct{}{}
		}
		out := map[string]struct{}{}
		for zone, ips := range zoneIPs {
			for ip := range ips {
				if _, ok := want[ip]; ok {
					out[zone] = struct{}{}
					break
				}
			}
		}
		return out
	}

	res.SharedExcluded = len(built.SharedExcluded)
	if len(built.SharedExcluded) > 0 {
		zones := zonesOf(built.SharedExcluded)
		p.infof("共享 anycast 权威排除出直连集合 %d 个地址（涉及 %d 个区域，仍保留在 ECS 白名单）",
			len(built.SharedExcluded), len(zones))
		p.infof("  地址：%s", joinSample(sharedSet, 8))
		p.infof("  区域：%s", joinSample(zones, 8))
	} else if len(shared.addrs) == 0 {
		p.warnf("共享 anycast 清单为空或不可读，本轮不排除任何权威（fail-open）")
	}

	res.DisputedCut = len(built.DisputedExcluded)
	if len(built.DisputedExcluded) > 0 {
		zones := zonesOf(built.DisputedExcluded)
		set := map[string]struct{}{}
		for _, ip := range built.DisputedExcluded {
			set[ip] = struct{}{}
		}
		p.infof("多源争议权威排除出 ECS 白名单 %d 个地址（涉及 %d 个区域，仍保留在直连集合）",
			len(built.DisputedExcluded), len(zones))
		p.infof("  地址：%s", joinSample(set, 8))
		p.infof("  区域：%s", joinSample(zones, 8))
	}

	res.PromotedUsed = len(built.PromotedUsed)
	if len(built.PromotedUsed) > 0 {
		zones := zonesOf(built.PromotedUsed)
		set := map[string]struct{}{}
		for _, ip := range built.PromotedUsed {
			set[ip] = struct{}{}
		}
		p.infof("多源晋级权威采信 %d 个地址（涉及 %d 个区域，direct4 未收录但全部归属库判为大陆）",
			len(built.PromotedUsed), len(zones))
		p.infof("  地址：%s", joinSample(set, 8))
	}

	ecsTargets := map[netip.Prefix]struct{}{}
	for _, prefix := range built.ECSPrefixes {
		ecsTargets[prefix] = struct{}{}
	}
	p.infof("ECS 白名单纳入 direct4 大陆网段 %d 条（消除冷启动窗口）", built.DirectECSPrefixes)
	if built.DirectECSCutAddrs > 0 {
		p.infof("其中扣除多源争议网段 %d 个地址（争议清单共 %d 个，落在 direct4 内的部分被扣）",
			built.DirectECSCutAddrs, disputed.Set.AddressCount())
	}

	accumKept, accumState, err := applyAccumulation(p, opt, ecsTargets, disputed.Set, now)
	if err != nil {
		return res, err
	}
	res.AccumKept = len(accumKept)
	for prefix := range accumKept {
		ecsTargets[prefix] = struct{}{}
	}
	if err := writeAccumState(p, opt.ECSStatePath, accumState); err != nil {
		return res, err
	}

	if err := writeECSConf(opt.ECSOutPath, ecsTargets); err != nil {
		return res, err
	}
	res.ECSPrefixes = len(collapsePrefixes(ecsTargets))

	var routeBody strings.Builder
	for _, prefix := range built.RoutePrefixes {
		routeBody.WriteString(prefix.String())
		routeBody.WriteString("\n")
	}
	if err := os.WriteFile(opt.ResultPath, []byte(routeBody.String()), 0o644); err != nil {
		return res, err
	}
	res.RoutePrefixes = len(built.RoutePrefixes)

	var matchedBody strings.Builder
	for _, zone := range built.MatchedZones {
		matchedBody.WriteString(zone.Name)
		matchedBody.WriteString("\n")
	}
	if err := os.WriteFile(opt.MatchedPath, []byte(matchedBody.String()), 0o644); err != nil {
		return res, err
	}
	res.MatchedZones = len(built.MatchedZones)

	if len(built.Defective) > 0 {
		total := 0
		reasons := make([]string, 0, len(built.Defective))
		for reason, zones := range built.Defective {
			total += len(zones)
			reasons = append(reasons, reason)
		}
		sort.Strings(reasons)
		p.infof("形态判据剔除区域 %d 个（不是可注册域，不参与墙内判定）", total)
		for _, reason := range reasons {
			zones := built.Defective[reason]
			sample := zones
			more := ""
			if len(sample) > 8 {
				sample = sample[:8]
				more = fmt.Sprintf(" …等 %d 个", len(zones))
			}
			p.infof("  %s: %s%s", reason, strings.Join(sample, ", "), more)
		}
	}

	forced := 0
	for _, zone := range built.MatchedZones {
		if zone.Forced {
			forced++
		}
	}
	res.ForcedZones = forced
	suffix := ""
	if forced > 0 {
		suffix = fmt.Sprintf("（其中 %d 个由人工指定）", forced)
	}
	p.infof("判定为墙内区域：%d / %d 个%s", len(built.MatchedZones), len(zoneIPs), suffix)
	for i, zone := range built.MatchedZones {
		if i >= 15 {
			p.infof("  … 另有 %d 个", len(built.MatchedZones)-15)
			break
		}
		p.infof("  %s（%d 台权威）", zone.Name, zone.Count)
	}

	res.DeadZones = len(built.DeadZones)
	if !built.RTOSeen {
		p.warnf("infra cache 里取不到 rto 字段，本轮跳过「权威全部不响应」过滤。Unbound 版本可能变了，请核对 dump_infra 的输出格式")
	} else {
		p.infof("权威全部不响应而被排除：%d 个", len(built.DeadZones))
		for i, zone := range built.DeadZones {
			if i >= 10 {
				p.infof("  … 另有 %d 个", len(built.DeadZones)-10)
				break
			}
			p.infof("  %s（%d 台权威 rto 全部到上限 %dms）", zone, len(zoneIPs[zone]), ruleset.DeadRTOMillis)
		}
	}
	p.infof("权威网段：%d 条", len(built.RoutePrefixes))
	return res, nil
}

func collapsePrefixes(targets map[netip.Prefix]struct{}) []netip.Prefix {
	ranges := make([]ipset.Range, 0, len(targets))
	for prefix := range targets {
		if r, ok := ipset.PrefixRange(prefix); ok {
			ranges = append(ranges, r)
		}
	}
	return ipset.New(ranges).Prefixes()
}

func applyAccumulation(
	p printer, opt Options, ecsTargets map[netip.Prefix]struct{},
	disputed *ipset.Set, now time.Time,
) (map[netip.Prefix]struct{}, map[string]int64, error) {
	kept := map[netip.Prefix]struct{}{}
	nextState := map[string]int64{}

	prev := loadPrevECS(opt.PrevECSPath)
	if len(prev) == 0 {
		return kept, nextState, nil
	}
	live := ipset.New(func() []ipset.Range {
		out := make([]ipset.Range, 0, len(ecsTargets))
		for prefix := range ecsTargets {
			if r, ok := ipset.PrefixRange(prefix); ok {
				out = append(out, r)
			}
		}
		return out
	}())

	accumSince, stateOK := loadAccumState(opt.ECSStatePath)
	nowTS := now.Unix()
	expired, accumDisputed := 0, 0

	for prefix := range prev {
		if live.CoversPrefix(prefix) {
			continue
		}
		if disputed != nil && disputed.Contains(prefix.Addr()) {
			accumDisputed++
			continue
		}
		key := prefix.String()
		since, ok := accumSince[key]
		if !ok {
			since = nowTS
		}
		if stateOK && nowTS-since > int64(opt.AccumTTL.Seconds()) {
			expired++
			continue
		}
		kept[prefix] = struct{}{}
		nextState[key] = since
	}

	if len(ecsTargets)+len(kept) > opt.MaxECSEntries {
		p.warnf("ECS 白名单累积到 %d 条，超过上限 %d，本轮只用新结果 %d 条",
			len(ecsTargets)+len(kept), opt.MaxECSEntries, len(ecsTargets))
		return map[netip.Prefix]struct{}{}, map[string]int64{}, nil
	}
	if len(kept) > 0 {
		oldest := nowTS
		for _, since := range nextState {
			if since < oldest {
				oldest = since
			}
		}
		p.infof("ECS 白名单沿用累积 %d 条（infra cache 本轮未覆盖到，最久 %d 小时）",
			len(kept), (nowTS-oldest)/3600)
	}
	if accumDisputed > 0 {
		p.infof("ECS 累积保留中剔除多源争议地址 %d 条（它们来自上一版白名单，不受本轮 infra 覆盖面影响）",
			accumDisputed)
	}
	if expired > 0 {
		p.infof("ECS 累积过期清理 %d 条（连续 %d 小时未被直接命中）",
			expired, int(opt.AccumTTL.Hours()))
	}
	if !stateOK {
		p.warnf("ECS 累积状态文件读取失败，本轮不做过期清理（fail-open）")
	}
	return kept, nextState, nil
}

func writeAccumState(p printer, path string, state map[string]int64) error {
	keys := make([]string, 0, len(state))
	for key := range state {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&b, "%s\t%d\n", key, state[key])
	}
	if err := writeAtomic(path, []byte(b.String()), 0o644); err != nil {
		p.warnf("ECS 累积状态文件写入失败：%v", err)
	}
	return nil
}

func writeECSConf(path string, targets map[netip.Prefix]struct{}) error {
	var b strings.Builder
	b.WriteString("# 由 update-cn-authority.sh 自动生成，请勿手工编辑\n")
	b.WriteString("# 只有列在这里的权威会收到客户端子网(ECS)。\n")
	b.WriteString("server:\n")
	for _, prefix := range collapsePrefixes(targets) {
		fmt.Fprintf(&b, "    send-client-subnet: %s\n", prefix)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
