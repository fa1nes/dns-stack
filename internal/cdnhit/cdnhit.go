package cdnhit

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dns-stack/dns-stack/internal/cdnrules"
	"github.com/dns-stack/dns-stack/internal/dnswire"
	"github.com/dns-stack/dns-stack/internal/ipset"
)

const (
	DefaultResolver = "127.0.0.1:5335"

	BeijingTelecom = "219.141.136.0/24"
	BeijingUnicom  = "202.106.0.0/24"
	BeijingMobile  = "221.130.33.0/24"

	GuangdongUnicom = "113.108.10.0/24"

	defaultTimeout = 6 * time.Second
)

var (
	BeijingTelecom4  = netip.MustParsePrefix(BeijingTelecom)
	GuangdongUnicom4 = netip.MustParsePrefix(GuangdongUnicom)
)

type Vantage struct {
	Prefix string
	Label  string
}

var Vantages = []Vantage{
	{BeijingTelecom, "北京电信"},
	{BeijingUnicom, "北京联通"},
	{BeijingMobile, "北京移动"},
}

type Probe struct {
	Domain string
	Label  string
}

var DefaultProbes = []Probe{
	{"www.taobao.com", "淘宝"},
	{"www.qq.com", "腾讯"},
	{"www.baidu.com", "百度"},
	{"www.huawei.com", "华为"},
	{"www.apple.com", "Apple"},
	{"www.microsoft.com", "微软"},
	{"www.bing.com", "必应"},
	{"www.cloudflare.com", "Cloudflare"},
}

type Verdict string

const (
	VerdictMainland     Verdict = "mainland"
	VerdictNoSteering   Verdict = "no_steering"
	VerdictNoNode       Verdict = "no_node"
	VerdictNoEcho       Verdict = "no_echo"
	VerdictNotDelivered Verdict = "not_delivered"
	VerdictUnresolved   Verdict = "unresolved"
)

func (v Verdict) Label() string {
	switch v {
	case VerdictMainland:
		return "拿到了国内节点"
	case VerdictNoSteering:
		return "权威不分地区，所有人拿到同一个地址"
	case VerdictNoEcho:
		return "答案来自缓存，看不出是否按地区挑过，复核会清缓存重查"
	case VerdictNotDelivered:
		return "清了缓存重查，权威仍没收到你的子网，ECS 白名单可能漏了它"
	case VerdictNoNode:
		return "按你的地区挑过了仍给境外，这家在国内没有节点"
	default:
		return "这次没解析出地址"
	}
}

func (v Verdict) Short() string {
	switch v {
	case VerdictMainland:
		return "国内节点"
	case VerdictNoSteering:
		return "不分地区"
	case VerdictNoEcho:
		return "待复核"
	case VerdictNotDelivered:
		return "子网没送到"
	case VerdictNoNode:
		return "无国内节点"
	default:
		return "解析失败"
	}
}

func (v Verdict) Decided() bool {
	return v == VerdictMainland || v == VerdictNoSteering ||
		v == VerdictNoNode || v == VerdictNotDelivered
}

type Outcome struct {
	Domain       string   `json:"domain"`
	Label        string   `json:"label"`
	Provider     string   `json:"provider"`
	ProviderID   string   `json:"provider_id"`
	HasMainland  bool     `json:"has_mainland"`
	MainlandNum  int      `json:"mainland_prefixes"`
	Addrs        []string `json:"addrs"`
	Scope        int      `json:"ecs_scope"`
	ECSEchoed    bool     `json:"ecs_echoed"`
	Flushed      bool     `json:"flushed"`
	FlushError   string   `json:"flush_error,omitempty"`
	Prefix       string   `json:"prefix,omitempty"`
	Foreign      bool     `json:"foreign"`
	Mismatch     bool     `json:"mismatch"`
	Verdict      Verdict  `json:"verdict"`
	VerdictText  string   `json:"verdict_text"`
	VerdictShort string   `json:"verdict_short"`
	Geo          string   `json:"geo,omitempty"`
	Error        string   `json:"error,omitempty"`
}

type Report struct {
	Resolver     string    `json:"resolver"`
	Subnet       string    `json:"subnet"`
	GeneratedAt  int64     `json:"generated_at"`
	RulesetAt    int64     `json:"ruleset_at"`
	Fresh        bool      `json:"fresh"`
	Probes       []Outcome `json:"probes"`
	Mainland     int       `json:"mainland"`
	NoNode       int       `json:"no_node"`
	NoSteering   int       `json:"no_steering"`
	NotDelivered int       `json:"not_delivered"`
	Undecided    int       `json:"undecided"`
	Comparable   int       `json:"comparable"`
}

type Answer struct {
	Addrs []netip.Addr

	Scope int

	Echoed bool

	Chain []string
}

type Resolver func(ctx context.Context, name string, subnet netip.Prefix) (Answer, error)

type Flusher func(ctx context.Context, name string) error

type Options struct {
	Resolver string
	Subnet   string
	Probes   []Probe
	Set      *cdnrules.Set
	Mainland *ipset.Set
	Timeout  time.Duration
	Now      func() time.Time
	Resolve  Resolver
	Flush    Flusher
}

func LoadMainland(path string) (*ipset.Set, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	loaded, err := ipset.LoadReader(file, ipset.LoadOptions{GlobalOnly: true})
	if err != nil {
		return nil, err
	}
	if loaded.Set == nil || loaded.Set.Len() == 0 {
		return nil, fmt.Errorf("%s 里没有任何有效的大陆网段", path)
	}
	return loaded.Set, nil
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func Run(ctx context.Context, opt Options) (Report, error) {
	if opt.Subnet == "" {
		opt.Subnet = BeijingTelecom
	}
	reports, err := RunAll(ctx, opt, []string{opt.Subnet})
	if err != nil {
		return Report{}, err
	}
	return reports[0], nil
}

type flushState struct {
	done bool
	err  string
}

func RunAll(ctx context.Context, opt Options, subnets []string) ([]Report, error) {
	if opt.Set.Empty() {
		return nil, fmt.Errorf("没有可用的 CDN 直连规则集，判据无法回答任何问题")
	}
	if opt.Resolver == "" {
		opt.Resolver = DefaultResolver
	}
	if opt.Timeout <= 0 {
		opt.Timeout = defaultTimeout
	}
	if opt.Resolve == nil {
		opt.Resolve = func(ctx context.Context, name string, subnet netip.Prefix) (Answer, error) {
			return Query(ctx, opt.Resolver, name, subnet, opt.Timeout)
		}
	}
	probes := opt.Probes
	if len(probes) == 0 {
		probes = DefaultProbes
	}
	prefixes := make([]netip.Prefix, 0, len(subnets))
	for _, raw := range subnets {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("客户端子网 %q 无法解析: %w", raw, err)
		}
		if !prefix.Addr().Is4() {
			return nil, fmt.Errorf("客户端子网必须是 IPv4，收到 %s", raw)
		}
		prefixes = append(prefixes, prefix)
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("没有给出任何客户端子网")
	}

	flushed := make([]flushState, len(probes))
	if opt.Flush != nil {
		var wg sync.WaitGroup
		for i, probe := range probes {
			wg.Add(1)
			go func(slot int, p Probe) {
				defer wg.Done()
				flushed[slot].done = true
				for _, name := range flushTargets(ctx, opt, p.Domain, prefixes[0]) {
					if err := opt.Flush(ctx, name); err != nil {
						flushed[slot] = flushState{err: err.Error()}
						return
					}
				}
			}(i, probe)
		}
		wg.Wait()
	}

	reports := make([]Report, len(prefixes))
	var wg sync.WaitGroup
	for r, prefix := range prefixes {
		reports[r] = Report{
			Resolver:    opt.Resolver,
			Subnet:      prefix.Masked().String(),
			GeneratedAt: opt.now().Unix(),
			RulesetAt:   opt.Set.GeneratedAt().Unix(),
			Fresh:       opt.Flush != nil,
			Probes:      make([]Outcome, len(probes)),
		}
		for i, probe := range probes {
			wg.Add(1)
			go func(r, slot int, prefix netip.Prefix, p Probe) {
				defer wg.Done()
				reports[r].Probes[slot] = classify(ctx, opt, prefix, p, flushed[slot])
			}(r, i, prefix, probe)
		}
	}
	wg.Wait()
	for r := range reports {
		tallyReport(&reports[r])
	}
	return reports, nil
}

func tallyReport(report *Report) {
	for _, item := range report.Probes {
		switch item.Verdict {
		case VerdictMainland:
			report.Mainland++
		case VerdictNoNode:
			report.NoNode++
		case VerdictNoSteering:
			report.NoSteering++
		case VerdictNotDelivered:
			report.NotDelivered++
		default:
			report.Undecided++
		}
		if item.Verdict.Decided() {
			report.Comparable++
		}
	}
}

func classify(ctx context.Context, opt Options, subnet netip.Prefix, probe Probe, flush flushState) Outcome {
	out := Outcome{Domain: probe.Domain, Label: probe.Label, Flushed: flush.done, FlushError: flush.err}
	if provider, known := opt.Set.ProviderFor(probe.Domain); known {
		out.Provider, out.ProviderID = provider.Name, provider.ID
		out.HasMainland, out.MainlandNum = provider.ServesMainland(), len(provider.Mainland)
	}

	answer, err := opt.Resolve(ctx, probe.Domain, subnet)
	addrs := answer.Addrs
	out.Scope, out.ECSEchoed = answer.Scope, answer.Echoed
	if err != nil || len(addrs) == 0 {
		out.Verdict = VerdictUnresolved
		if err != nil {
			out.Error = err.Error()
		}
		out.VerdictText, out.VerdictShort = out.Verdict.Label(), out.Verdict.Short()
		return out
	}
	for _, addr := range addrs {
		out.Addrs = append(out.Addrs, addr.String())
	}

	unowned := 0
	for _, addr := range addrs {
		owner, prefix, inRulesetMainland, hit := opt.Set.Owner(addr)
		if hit {
			if out.ProviderID == "" {
				out.Provider, out.ProviderID = owner.Name, owner.ID
				out.HasMainland, out.MainlandNum = owner.ServesMainland(), len(owner.Mainland)
			}
			if out.Prefix == "" {
				out.Prefix = prefix.String()
			}
		} else {
			unowned++
		}

		if inRulesetMainland || (opt.Mainland != nil && opt.Mainland.Contains(addr)) {
			out.Verdict = VerdictMainland
			out.VerdictText, out.VerdictShort = out.Verdict.Label(), out.Verdict.Short()
			return out
		}
	}

	out.Foreign = opt.Mainland != nil
	out.Mismatch = out.Foreign && out.ProviderID != "" && unowned == len(addrs)

	switch {
	case !answer.Echoed && out.Flushed:
		out.Verdict = VerdictNotDelivered
	case !answer.Echoed:
		out.Verdict = VerdictNoEcho
	case answer.Scope == 0:
		out.Verdict = VerdictNoSteering
	default:
		out.Verdict = VerdictNoNode
	}
	out.VerdictText, out.VerdictShort = out.Verdict.Label(), out.Verdict.Short()
	return out
}

func flushTargets(ctx context.Context, opt Options, name string, subnet netip.Prefix) []string {
	targets := []string{name}
	seen := map[string]bool{strings.ToLower(strings.TrimSuffix(name, ".")): true}
	prime, err := opt.Resolve(ctx, name, subnet)
	if err != nil {
		return targets
	}
	for _, link := range prime.Chain {
		key := strings.ToLower(strings.TrimSuffix(link, "."))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		targets = append(targets, key)
	}
	return targets
}

func Query(ctx context.Context, server, name string, subnet netip.Prefix, timeout time.Duration) (Answer, error) {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	packet, err := dnswire.BuildQueryWithSubnet(uint16(rand.Uint32()), name, dnswire.TypeA, subnet)
	if err != nil {
		return Answer{}, err
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", server)
	if err != nil {
		return Answer{}, err
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if due, ok := ctx.Deadline(); ok && due.Before(deadline) {
		deadline = due
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(packet); err != nil {
		return Answer{}, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return Answer{}, err
	}
	msg, err := dnswire.Unpack(buf[:n])
	if err != nil {
		return Answer{}, err
	}
	out := Answer{}
	for _, rr := range msg.Answers {
		if addr, ok := rr.A(); ok {
			out.Addrs = append(out.Addrs, addr)
		}
		if rr.Type == dnswire.TypeCNAME {
			if target, ok := rr.TargetName(buf[:n]); ok {
				out.Chain = append(out.Chain, target)
			}
		}
	}
	sort.Slice(out.Addrs, func(i, j int) bool { return out.Addrs[i].Compare(out.Addrs[j]) < 0 })
	if ecs, ok := msg.ClientSubnet(); ok {
		out.Scope, out.Echoed = ecs.Scope, true
	}
	return out, nil
}

func JoinAddrs(addrs []netip.Addr, sep string) string {
	parts := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		parts = append(parts, addr.String())
	}
	return strings.Join(parts, sep)
}
