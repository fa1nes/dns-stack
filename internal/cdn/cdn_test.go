package cdn

import "testing"

func TestSuffixMatchingRespectsLabelBoundaries(t *testing.T) {
	shouldMatch := []string{
		"fastly.net", "a.b.fastly.net", "akamaiedge.net", "edge.akamaiedge.net",
		"alicdn.com", "img.alicdn.com", "aliyuncs.com", "example.com",
	}
	for _, name := range shouldMatch {
		if !IsSharedTenancy(name) {
			t.Errorf("%s 应当被识别为多租户共享根域", name)
		}
	}
	shouldNotMatch := []string{
		"notfastly.net", "evil-example.com", "fastly.net.evil.com",
		"myakamaiedge.net", "qq.com", "baidu.com", "net", "com",
	}
	for _, name := range shouldNotMatch {
		if IsSharedTenancy(name) {
			t.Errorf("%s 不该命中共享根域判据（按标签边界匹配才不会误伤）", name)
		}
	}
}

func TestGeoSteeringRootsAreAlwaysSharedTenancy(t *testing.T) {
	for _, root := range geoSteeringRoots {
		if !IsGeoSteered(root) {
			t.Errorf("%s 应当带 geo-steering 标志", root)
		}
		if !IsSharedTenancy(root) {
			t.Errorf("%s 带 geo-steering 却不带多租户标志——这两个集合的包含关系必须由构造保证", root)
		}
	}
	if IsGeoSteered("qq.com") {
		t.Error("普通域名不该被当成 geo-steering 链")
	}
}

func TestAkamaiAuthorityChainIsFullyCovered(t *testing.T) {
	chain := []string{
		"akam.net", "a13-65.akam.net", "usw6.akam.net",
		"akamaiedge.net", "a28-192.akamaiedge.net",
		"edgekey.net", "www.microsoft.com-c-3.edgekey.net",
		"akadns.net", "a1-128.akadns.net",
		"akamai.net", "edgesuite.net", "akamaized.net", "akagtm.org",
	}
	for _, name := range chain {
		if !IsGeoSteered(name) {
			t.Errorf("%s 在 Akamai 权威链上却不带 geo-steering 标志——它的权威会收不到 ECS", name)
		}
	}
}

func TestAppleAndAzureChainsAreCovered(t *testing.T) {
	for _, name := range []string{
		"aaplimg.com", "apple-dns.net", "cdn-apple.com",
		"azure-dns.com", "ns1-206.azure-dns.com", "azure-dns.net",
		"trafficmanager.net", "azureedge.net",
	} {
		if !IsGeoSteered(name) {
			t.Errorf("%s 应当带 geo-steering 标志", name)
		}
	}
}

func TestTrailingDotAndCaseAreNormalised(t *testing.T) {
	for _, name := range []string{"AKAMAIEDGE.NET", "akamaiedge.net.", "A28-192.AkamaiEdge.Net."} {
		if !IsGeoSteered(name) {
			t.Errorf("%s 规范化后应当命中（infra cache 给的 zone 带尾点且大小写不定）", name)
		}
	}
}

func TestSharedDNSProviderCoversAkamaiFleet(t *testing.T) {
	for _, asn := range []int{20940, 16625, 21342, 35994} {
		if label, ok := SharedDNSProvider(asn); !ok || label != "Akamai" {
			t.Errorf("AS%d 应当识别为 Akamai，得到 %q/%v", asn, label, ok)
		}
	}
	if _, ok := SharedDNSProvider(4134); ok {
		t.Error("中国电信 AS4134 不是共享 DNS provider")
	}
}
