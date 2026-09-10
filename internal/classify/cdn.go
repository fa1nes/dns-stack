package classify

import "strings"

type providerTrait uint8

const (
	traitSharedTenancy providerTrait = 1 << iota
	traitGeoSteering
)

var geoSteeringRoots = []string{
	"akadns.net", "akamai.net", "akamaiedge.net", "akamaihd.net",
	"akamaized.net", "akagtm.org", "edgekey.net", "edgesuite.net",
	"cloudfront.net", "cloudflare.net", "fastly.net", "fastlylb.net",
	"azureedge.net", "azurefd.net", "tm-azurefd.net", "trafficmanager.net",
	"aaplimg.com", "apple-dns.net", "cdn77.org", "incapdns.net", "gcdn.co",
	"alicdn.com", "alikunlun.com", "kunlunsl.com", "kunlunca.com", "kunlunar.com",
	"wscdns.com", "lxdns.com", "cdn20.com", "bdydns.com", "qiniudns.com",
	"myqcloud.com", "qcloudcdn.com", "ourdvsss.com", "tcdnvod.com", "cdngslb.com",
	"cdnhwc1.com", "cdnhwc2.com", "cdnhwc3.com", "cdnhwc5.com",
}

var sharedTenancyRoots = []string{
	"apple.com", "apple-cloudkit.com", "icloud.com", "mzstatic.com",
	"akamai.com", "akamaistream.net", "akamaitechnologies.com", "cloudflare.com",
	"amazonaws.com", "googleapis.com", "githubusercontent.com",
	"unpkg.com", "jsdelivr.net", "jsdelivr.com", "cdnjs.com", "bootstrapcdn.com",
	"esm.sh", "skypack.dev", "jspm.io", "statically.io",
	"b-cdn.net", "bunnycdn.com", "cachefly.net", "edgecastcdn.net",
	"footprint.net", "llnwd.net", "hwcdn.net", "stackpathcdn.com",
	"netdna-cdn.com", "netdna-ssl.com", "kxcdn.com", "gcorelabs.com",
	"fbcdn.net", "cdninstagram.com", "twimg.com", "googlevideo.com",
	"gvt1.com", "gvt2.com", "ggpht.com", "dns.google",
	"github.com", "githubassets.com", "gitlab-static.net",
	"alicdn.net", "aliyuncs.com", "bcebos.com", "qiniucdn.com", "qbox.me",
	"upaiyun.com", "example.com", "example.net", "example.org",
}

var providerSuffixes = buildProviderTable()

func buildProviderTable() map[string]providerTrait {
	table := make(map[string]providerTrait, len(geoSteeringRoots)+len(sharedTenancyRoots))
	for _, root := range geoSteeringRoots {
		table[root] = traitSharedTenancy | traitGeoSteering
	}
	for _, root := range sharedTenancyRoots {
		table[root] |= traitSharedTenancy
	}
	return table
}

func providerTraits(name string) providerTrait {
	var out providerTrait
	for rest := name; rest != ""; {
		out |= providerSuffixes[rest]
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			break
		}
		rest = rest[dot+1:]
	}
	return out
}

func IsSharedTenancyRoot(name string) bool {
	return providerTraits(name)&traitSharedTenancy != 0
}

func isGeoSteered(name string) bool {
	return providerTraits(name)&traitGeoSteering != 0
}
