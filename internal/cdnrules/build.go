package cdnrules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/cdn"
	"github.com/dns-stack/dns-stack/internal/cidrutil"
)

const (
	minV4Bits = 8
	minV6Bits = 16
	maxBody   = 64 << 20
)

type Fetcher func(ctx context.Context, url string) ([]byte, error)

type feed struct {
	URL    string
	Decode func([]byte) ([]netip.Prefix, error)
}

var officialFeeds = map[string][]feed{
	"cloudflare": {
		{URL: "https://www.cloudflare.com/ips-v4", Decode: decodePlain},
		{URL: "https://www.cloudflare.com/ips-v6", Decode: decodePlain},
	},
	"fastly": {
		{URL: "https://api.fastly.com/public-ip-list", Decode: decodeFastly},
	},
	"amazon": {
		{URL: "https://ip-ranges.amazonaws.com/ip-ranges.json", Decode: decodeCloudFront},
	},
}

type Options struct {
	Fetch       Fetcher
	Mainland    []netip.Prefix
	Now         time.Time
	ASNEndpoint string
	MinPrefixes int
}

type Report struct {
	Providers   []Provider
	Warnings    []string
	Prefixes    int
	Domains     int
	WithNets    []string
	WithoutNets []string
}

func Build(ctx context.Context, opt Options) (Report, error) {
	if opt.Fetch == nil {
		opt.Fetch = HTTPFetcher(30 * time.Second)
	}
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	if opt.ASNEndpoint == "" {
		opt.ASNEndpoint = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS"
	}
	if len(opt.Mainland) == 0 {
		return Report{}, fmt.Errorf("缺少大陆网段基线，无法区分 CDN 的大陆与境外节点")
	}
	mainland := cidrutil.CollapsePrefixes(opt.Mainland)

	var rep Report
	for _, op := range cdn.Operators() {
		p := Provider{ID: op.ID, Name: op.Name, Domains: op.Roots}
		var raw []netip.Prefix
		for _, f := range officialFeeds[op.ID] {
			got, err := fetchPrefixes(ctx, opt.Fetch, f.URL, f.Decode)
			if err != nil {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("%s 官方前缀源 %s 失败: %v", op.ID, f.URL, err))
				continue
			}
			raw = append(raw, got...)
		}
		for _, asn := range op.ASNs {
			url := fmt.Sprintf("%s%d", opt.ASNEndpoint, asn)
			got, err := fetchPrefixes(ctx, opt.Fetch, url, decodeRIPEStat)
			if err != nil {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("%s AS%d 前缀拉取失败: %v", op.ID, asn, err))
				continue
			}
			raw = append(raw, got...)
		}
		raw = cidrutil.CollapsePrefixes(raw)
		p.Mainland = cidrutil.Intersect(raw, mainland)
		p.Offshore = cidrutil.Subtract(raw, mainland)
		rep.Providers = append(rep.Providers, p)
		rep.Prefixes += p.PrefixCount()
		rep.Domains += len(p.Domains)
		if p.PrefixCount() > 0 {
			rep.WithNets = append(rep.WithNets, op.ID)
		} else {
			rep.WithoutNets = append(rep.WithoutNets, op.ID)
		}
	}
	sort.Strings(rep.WithNets)
	sort.Strings(rep.WithoutNets)
	if opt.MinPrefixes > 0 && rep.Prefixes < opt.MinPrefixes {
		return rep, fmt.Errorf("只收集到 %d 条前缀，低于下限 %d；发布这样的规则集等于把判据变成永远弃权",
			rep.Prefixes, opt.MinPrefixes)
	}
	return rep, nil
}

func fetchPrefixes(ctx context.Context, fetch Fetcher, url string, decode func([]byte) ([]netip.Prefix, error)) ([]netip.Prefix, error) {
	body, err := fetch(ctx, url)
	if err != nil {
		return nil, err
	}
	list, err := decode(body)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, 0, len(list))
	for _, p := range list {
		if !p.IsValid() {
			continue
		}
		if p.Addr().Is6() {
			if p.Bits() < minV6Bits {
				return nil, fmt.Errorf("前缀 %s 比 /%d 还宽，拒绝整条来源", p, minV6Bits)
			}
		} else if p.Bits() < minV4Bits {
			return nil, fmt.Errorf("前缀 %s 比 /%d 还宽，拒绝整条来源", p, minV4Bits)
		}
		out = append(out, p.Masked())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("来源解析后没有任何前缀")
	}
	return out, nil
}

func HTTPFetcher(timeout time.Duration) Fetcher {
	client := &http.Client{Timeout: timeout}
	return func(ctx context.Context, url string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "dns-stack")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, maxBody))
	}
}

func decodePlain(body []byte) ([]netip.Prefix, error) {
	return cidrutil.ReadPrefixes(strings.NewReader(string(body)))
}

func decodeFastly(body []byte) ([]netip.Prefix, error) {
	var doc struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	return parseAll(append(append([]string(nil), doc.Addresses...), doc.IPv6Addresses...))
}

func decodeCloudFront(body []byte) ([]netip.Prefix, error) {
	var doc struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Service  string `json:"service"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
			Service    string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var values []string
	for _, p := range doc.Prefixes {
		if p.Service == "CLOUDFRONT" {
			values = append(values, p.IPPrefix)
		}
	}
	for _, p := range doc.IPv6Prefixes {
		if p.Service == "CLOUDFRONT" {
			values = append(values, p.IPv6Prefix)
		}
	}
	return parseAll(values)
}

func decodeRIPEStat(body []byte) ([]netip.Prefix, error) {
	var doc struct {
		Status string `json:"status"`
		Data   struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	if doc.Status != "" && doc.Status != "ok" {
		return nil, fmt.Errorf("RIPEstat 返回 status=%q", doc.Status)
	}
	values := make([]string, 0, len(doc.Data.Prefixes))
	for _, p := range doc.Data.Prefixes {
		values = append(values, p.Prefix)
	}
	return parseAll(values)
}

func parseAll(values []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		p, err := cidrutil.ParsePrefix(v)
		if err != nil {
			return nil, fmt.Errorf("无法解析前缀 %q: %w", v, err)
		}
		out = append(out, p)
	}
	return out, nil
}
