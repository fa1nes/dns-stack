package cdn

import "strings"

type Trait uint8

const (
	TraitSharedTenancy Trait = 1 << iota
	TraitGeoSteering
)

var geoSteeringRoots = []string{
	"akadns.net", "akadns6.net", "akagtm.org", "akam.net", "akamai.net",
	"akamaiedge.net", "akamaiedge-staging.net", "akamaihd.net", "akamaized.net",
	"akamaistream.net", "akamaitechnologies.com", "akaquill.net",
	"edgekey.net", "edgekey-staging.net", "edgesuite.net",

	"aaplimg.com", "apple-dns.net", "cdn-apple.com",

	"azure-dns.com", "azure-dns.net", "azure-dns.org", "azure-dns.info",
	"azureedge.net", "azurefd.net", "tm-azurefd.net", "trafficmanager.net",
	"msedge.net", "a-msedge.net", "l-msedge.net", "s-msedge.net",

	"cloudfront.net", "cloudflare.net", "fastly.net", "fastlylb.net",
	"cdn77.org", "incapdns.net", "impervadns.net", "gcdn.co", "gcorelabs.com",
	"b-cdn.net", "bunnycdn.com", "cachefly.net", "edgecastcdn.net",
	"footprint.net", "llnwd.net", "hwcdn.net", "stackpathcdn.com",

	"alicdn.com", "alikunlun.com", "kunlunsl.com", "kunlunca.com", "kunlunar.com",
	"alidns.com", "hichina.com", "aliyuncs.com",
	"wscdns.com", "lxdns.com", "cdn20.com", "bdydns.com", "qiniudns.com",
	"myqcloud.com", "qcloudcdn.com", "ourdvsss.com", "tcdnvod.com", "cdngslb.com",
	"cdntip.com", "dnsv1.com", "dnsv2.com", "dnsv3.com", "dnsv4.com", "dnsv5.com",
	"cdnhwc1.com", "cdnhwc2.com", "cdnhwc3.com", "cdnhwc5.com",
	"dbankcdn.cn", "dbankcdn.com", "livehwc3.cn",
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

var suffixes = buildTable()

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

func Traits(name string) Trait {
	var out Trait
	for rest := strings.ToLower(strings.TrimRight(name, ".")); rest != ""; {
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

var sharedDNSAS = map[int]string{
	16509: "AWS", 14618: "AWS", 7224: "AWS",
	20940: "Akamai", 21342: "Akamai", 16625: "Akamai", 35994: "Akamai",
	32787: "Akamai", 12222: "Akamai", 16702: "Akamai", 33905: "Akamai",
	13335: "Cloudflare",
	26496: "GoDaddy", 398101: "GoDaddy",
	33517: "Dyn", 33070: "Dyn",
	30060: "Verisign",
	19551: "Incapsula",
	54113: "Fastly", 394192: "Fastly",
	8068: "Microsoft", 8075: "Microsoft",
}

func SharedDNSProvider(asn int) (string, bool) {
	label, ok := sharedDNSAS[asn]
	return label, ok
}
