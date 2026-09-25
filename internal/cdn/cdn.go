package cdn

import (
	"sort"
	"strings"

	"github.com/dns-stack/dns-stack/internal/domain"
)

type Trait uint8

const (
	TraitSharedTenancy Trait = 1 << iota
	TraitGeoSteering
)

type Operator struct {
	ID    string
	Name  string
	Roots []string

	ASNs []int

	PrefixASNs []int
}

func (o Operator) AllASNs() []int {
	out := make([]int, 0, len(o.ASNs)+len(o.PrefixASNs))
	out = append(out, o.ASNs...)
	out = append(out, o.PrefixASNs...)
	return out
}

var operators = []Operator{
	{
		ID: "akamai", Name: "Akamai",
		Roots: []string{
			"akadns.net", "akadns6.net", "akagtm.org", "akam.net", "akamai.net",
			"akamaiedge.net", "akamaiedge-staging.net", "akamaihd.net", "akamaized.net",
			"akamaistream.net", "akamaitechnologies.com", "akaquill.net",
			"edgekey.net", "edgekey-staging.net", "edgesuite.net",
		},
		ASNs: []int{12222, 16625, 16702, 20940, 21342, 32787, 33905, 35994},
	},
	{
		ID: "apple", Name: "Apple",
		Roots:      []string{"aaplimg.com", "apple-dns.net", "cdn-apple.com"},
		PrefixASNs: []int{714, 6185},
	},
	{
		ID: "microsoft", Name: "Microsoft",
		Roots: []string{
			"azure-dns.com", "azure-dns.net", "azure-dns.org", "azure-dns.info",
			"azureedge.net", "azurefd.net", "tm-azurefd.net", "trafficmanager.net",
			"msedge.net", "a-msedge.net", "l-msedge.net", "s-msedge.net",
		},
		ASNs: []int{8068, 8075},
	},
	{
		ID: "amazon", Name: "AWS",
		Roots: []string{"cloudfront.net"},
		ASNs:  []int{7224, 14618, 16509},
	},
	{
		ID: "cloudflare", Name: "Cloudflare",
		Roots: []string{"cloudflare.net"},
		ASNs:  []int{13335},
	},
	{
		ID: "fastly", Name: "Fastly",
		Roots: []string{"fastly.net", "fastlylb.net"},
		ASNs:  []int{54113, 394192},
	},
	{
		ID: "imperva", Name: "Imperva",
		Roots: []string{"incapdns.net", "impervadns.net"},
		ASNs:  []int{19551},
	},
	{
		ID: "cdn77", Name: "CDN77",
		Roots: []string{"cdn77.org"},
	},
	{
		ID: "gcore", Name: "G-Core",
		Roots: []string{"gcdn.co", "gcorelabs.com"},
	},
	{
		ID: "bunny", Name: "Bunny",
		Roots: []string{"b-cdn.net", "bunnycdn.com"},
	},
	{
		ID: "cachefly", Name: "CacheFly",
		Roots: []string{"cachefly.net"},
	},
	{
		ID: "edgecast", Name: "Edgecast",
		Roots: []string{"edgecastcdn.net"},
	},
	{
		ID: "edgio", Name: "Edgio",
		Roots: []string{"llnwd.net", "footprint.net"},
	},
	{
		ID: "stackpath", Name: "StackPath",
		Roots: []string{"hwcdn.net", "stackpathcdn.com"},
	},
	{
		ID: "alibaba", Name: "阿里云",
		Roots: []string{
			"alicdn.com", "alikunlun.com", "kunlunsl.com", "kunlunca.com", "kunlunar.com",
			"alidns.com", "hichina.com", "aliyuncs.com",
		},
		PrefixASNs: []int{24429, 37963, 45102},
	},
	{
		ID: "tencent", Name: "腾讯云",
		Roots: []string{
			"myqcloud.com", "qcloudcdn.com", "ourdvsss.com", "tcdnvod.com", "cdngslb.com",
			"cdntip.com", "dnsv1.com", "dnsv2.com", "dnsv3.com", "dnsv4.com", "dnsv5.com",
		},
		PrefixASNs: []int{45090, 132203, 132591},
	},
	{
		ID: "huawei", Name: "华为云",
		Roots: []string{
			"cdnhwc1.com", "cdnhwc2.com", "cdnhwc3.com", "cdnhwc5.com",
			"dbankcdn.cn", "dbankcdn.com", "livehwc3.cn",
		},
		PrefixASNs: []int{55990, 136907},
	},
	{
		ID: "wangsu", Name: "网宿",
		Roots: []string{"wscdns.com", "lxdns.com", "cdn20.com"},
	},
	{
		ID: "baidu", Name: "百度云",
		Roots:      []string{"bdydns.com"},
		PrefixASNs: []int{38365, 55967},
	},
	{
		ID: "qiniu", Name: "七牛云",
		Roots: []string{"qiniudns.com"},
	},
}

var dnsOnlyAS = map[int]string{
	26496: "GoDaddy", 398101: "GoDaddy",
	33517: "Dyn", 33070: "Dyn",
	30060: "Verisign",
}

var sharedTenancyRoots = []string{
	"apple.com", "apple-cloudkit.com", "icloud.com", "mzstatic.com",
	"akamai.com", "cloudflare.com",
	"amazonaws.com", "googleapis.com", "githubusercontent.com",
	"unpkg.com", "jsdelivr.net", "jsdelivr.com", "cdnjs.com", "bootstrapcdn.com",
	"esm.sh", "skypack.dev", "jspm.io", "statically.io",
	"netdna-cdn.com", "netdna-ssl.com", "kxcdn.com",
	"fbcdn.net", "cdninstagram.com", "twimg.com", "googlevideo.com",
	"gvt1.com", "gvt2.com", "ggpht.com", "dns.google",
	"github.com", "githubassets.com", "gitlab-static.net",
	"alicdn.net", "bcebos.com", "qiniucdn.com", "qbox.me",
	"upaiyun.com", "example.com", "example.net", "example.org",
}

var (
	geoSteeringRoots = collectRoots()
	suffixes         = buildTable()
	rootOwner        = buildRootOwner()
	sharedDNSAS      = buildSharedDNSAS()
)

func collectRoots() []string {
	out := make([]string, 0, 64)
	for _, op := range operators {
		out = append(out, op.Roots...)
	}
	return out
}

func buildTable() map[string]Trait {
	table := make(map[string]Trait, len(geoSteeringRoots)+len(sharedTenancyRoots))
	for _, root := range geoSteeringRoots {
		table[root] = TraitSharedTenancy | TraitGeoSteering
	}
	for _, root := range sharedTenancyRoots {
		table[root] |= TraitSharedTenancy
	}
	return table
}

func buildRootOwner() map[string]string {
	table := make(map[string]string, len(geoSteeringRoots))
	for _, op := range operators {
		for _, root := range op.Roots {
			table[root] = op.ID
		}
	}
	return table
}

func buildSharedDNSAS() map[int]string {
	table := make(map[int]string, len(dnsOnlyAS)+16)
	for asn, label := range dnsOnlyAS {
		table[asn] = label
	}
	for _, op := range operators {
		for _, asn := range op.ASNs {
			table[asn] = op.Name
		}
	}
	return table
}

func Traits(name string) Trait {
	var out Trait
	for rest := domain.Normalize(name); rest != ""; {
		out |= suffixes[rest]
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			break
		}
		rest = rest[dot+1:]
	}
	return out
}

func IsSharedTenancy(name string) bool { return Traits(name)&TraitSharedTenancy != 0 }

func IsGeoSteered(name string) bool { return Traits(name)&TraitGeoSteering != 0 }

func GeoSteeringRoots() []string {
	out := make([]string, len(geoSteeringRoots))
	copy(out, geoSteeringRoots)
	return out
}

func Operators() []Operator {
	out := make([]Operator, len(operators))
	for i, op := range operators {
		out[i] = Operator{
			ID:         op.ID,
			Name:       op.Name,
			Roots:      append([]string(nil), op.Roots...),
			ASNs:       append([]int(nil), op.ASNs...),
			PrefixASNs: append([]int(nil), op.PrefixASNs...),
		}
		sort.Strings(out[i].Roots)
		sort.Ints(out[i].ASNs)
		sort.Ints(out[i].PrefixASNs)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func OperatorFor(name string) (string, bool) {
	for rest := domain.Normalize(name); rest != ""; {
		if id, ok := rootOwner[rest]; ok {
			return id, true
		}
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			break
		}
		rest = rest[dot+1:]
	}
	return "", false
}

func SharedDNSProvider(asn int) (string, bool) {
	label, ok := sharedDNSAS[asn]
	return label, ok
}
