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

	BeijingTelecom  = "219.141.136.0/24"
	GuangdongUnicom = "113.108.10.0/24"

	defaultTimeout = 6 * time.Second
)

var (
	BeijingTelecomPrefix  = netip.MustParsePrefix(BeijingTelecom)
	GuangdongUnicomPrefix = netip.MustParsePrefix(GuangdongUnicom)
)

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
	VerdictMainland   Verdict = "mainland"
	VerdictStranded   Verdict = "stranded"
	VerdictOffshore   Verdict = "offshore"
	VerdictThin       Verdict = "thin"
	VerdictMismatch   Verdict = "mismatch"
	VerdictUnknown    Verdict = "unknown"
	VerdictUnresolved Verdict = "unresolved"
)

func (v Verdict) Label() string {
	switch v {
	case VerdictMainland:
		return "命中大陆节点"
	case VerdictStranded:
		return "该 CDN 有大陆节点，却拿到境外节点"
	case VerdictOffshore:
		return "境外节点（该 CDN 没有大陆段）"
	case VerdictThin:
		return "境外节点（该 CDN 的大陆段太少，判据弃权）"
	case VerdictMismatch:
		return "境外地址且不属于该 CDN"
	case VerdictUnknown:
		return "不在规则集内"
	default:
		return "未解析出地址"
	}
}

func (v Verdict) Bad() bool { return v == VerdictStranded }

type Outcome struct {
	Domain      string   `json:"domain"`
	Label       string   `json:"label"`
	Provider    string   `json:"provider"`
	ProviderID  string   `json:"provider_id"`
	HasMainland bool     `json:"has_mainland"`
	MainlandNum int      `json:"mainland_prefixes"`
	Addrs       []string `json:"addrs"`
	Prefix      string   `json:"prefix,omitempty"`
	Verdict     Verdict  `json:"verdict"`
	VerdictText string   `json:"verdict_text"`
	Error       string   `json:"error,omitempty"`
}

type Report struct {
	Resolver    string    `json:"resolver"`
	Subnet      string    `json:"subnet"`
	GeneratedAt int64     `json:"generated_at"`
	RulesetAt   int64     `json:"ruleset_at"`
	Probes      []Outcome `json:"probes"`
	Mainland    int       `json:"mainland"`
	Stranded    int       `json:"stranded"`
	Comparable  int       `json:"comparable"`
}

type Resolver func(ctx context.Context, name string, subnet netip.Prefix) ([]netip.Addr, error)

type Options struct {
	Resolver string
	Subnet   string
	Probes   []Probe
	Set      *cdnrules.Set
	Mainland *ipset.Set
	Timeout  time.Duration
	Now      func() time.Time
	Resolve  Resolver
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
	if opt.Set.Empty() {
		return Report{}, fmt.Errorf("没有可用的 CDN 直连规则集，判据无法回答任何问题")
	}
	if opt.Resolver == "" {
		opt.Resolver = DefaultResolver
	}
	if opt.Subnet == "" {
		opt.Subnet = BeijingTelecom
	}
	prefix, err := netip.ParsePrefix(opt.Subnet)
	if err != nil {
		return Report{}, fmt.Errorf("客户端子网 %q 无法解析: %w", opt.Subnet, err)
	}
	if !prefix.Addr().Is4() {
		return Report{}, fmt.Errorf("客户端子网必须是 IPv4，收到 %s", opt.Subnet)
	}
	if opt.Timeout <= 0 {
		opt.Timeout = defaultTimeout
	}
	if opt.Resolve == nil {
		opt.Resolve = func(ctx context.Context, name string, subnet netip.Prefix) ([]netip.Addr, error) {
			return Query(ctx, opt.Resolver, name, subnet, opt.Timeout)
		}
	}
	probes := opt.Probes
	if len(probes) == 0 {
		probes = DefaultProbes
	}

	report := Report{
		Resolver:    opt.Resolver,
		Subnet:      prefix.Masked().String(),
		GeneratedAt: opt.now().Unix(),
		RulesetAt:   opt.Set.GeneratedAt().Unix(),
	}
	report.Probes = make([]Outcome, len(probes))
	var wg sync.WaitGroup
	for i, probe := range probes {
		wg.Add(1)
		go func(slot int, p Probe) {
			defer wg.Done()
			report.Probes[slot] = classify(ctx, opt, prefix, p)
		}(i, probe)
	}
	wg.Wait()
	for _, item := range report.Probes {
		switch item.Verdict {
		case VerdictMainland:
			report.Mainland++
			report.Comparable++
		case VerdictStranded:
			report.Stranded++
			report.Comparable++
		}
	}
	return report, nil
}

func classify(ctx context.Context, opt Options, subnet netip.Prefix, probe Probe) Outcome {
	out := Outcome{Domain: probe.Domain, Label: probe.Label}
	if provider, known := opt.Set.ProviderFor(probe.Domain); known {
		out.Provider, out.ProviderID = provider.Name, provider.ID
		out.HasMainland, out.MainlandNum = provider.ServesMainland(), len(provider.Mainland)
	}

	addrs, err := opt.Resolve(ctx, probe.Domain, subnet)
	if err != nil || len(addrs) == 0 {
		out.Verdict = VerdictUnresolved
		if err != nil {
			out.Error = err.Error()
		}
		out.VerdictText = out.Verdict.Label()
		return out
	}
	for _, addr := range addrs {
		out.Addrs = append(out.Addrs, addr.String())
	}

	out.Verdict = VerdictUnknown
	for _, addr := range addrs {
		owner, prefix, inRulesetMainland, hit := opt.Set.Owner(addr)
		if hit && out.ProviderID == "" {
			out.Provider, out.ProviderID = owner.Name, owner.ID
			out.HasMainland, out.MainlandNum = owner.ServesMainland(), len(owner.Mainland)
		}

		if inRulesetMainland || (opt.Mainland != nil && opt.Mainland.Contains(addr)) {
			out.Verdict = VerdictMainland
			if hit {
				out.Prefix = prefix.String()
			}
			out.VerdictText = out.Verdict.Label()
			return out
		}

		if !hit {
			if out.Verdict == VerdictUnknown && out.ProviderID != "" && opt.Mainland != nil {
				out.Verdict = VerdictMismatch
			}
			continue
		}
		if out.Prefix == "" {
			out.Prefix = prefix.String()
		}
		switch {
		case owner.ServesMainland():
			out.Verdict = VerdictStranded
		case out.Verdict == VerdictStranded:
		case owner.HasMainland():
			out.Verdict = VerdictThin
		default:
			out.Verdict = VerdictOffshore
		}
	}
	out.VerdictText = out.Verdict.Label()
	return out
}

func Query(ctx context.Context, server, name string, subnet netip.Prefix, timeout time.Duration) ([]netip.Addr, error) {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	packet, err := dnswire.BuildQueryWithSubnet(uint16(rand.Uint32()), name, dnswire.TypeA, subnet)
	if err != nil {
		return nil, err
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if due, ok := ctx.Deadline(); ok && due.Before(deadline) {
		deadline = due
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	msg, err := dnswire.Unpack(buf[:n])
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, rr := range msg.Answers {
		if addr, ok := rr.A(); ok {
			out = append(out, addr)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
	return out, nil
}

func JoinAddrs(addrs []netip.Addr, sep string) string {
	parts := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		parts = append(parts, addr.String())
	}
	return strings.Join(parts, sep)
}
