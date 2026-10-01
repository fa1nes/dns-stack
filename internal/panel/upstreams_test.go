package panel

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const productionMetricsSample = `upstream_err_total{upstream="foreign-hk"} 11
upstream_err_total{upstream="local-unbound"} 31
upstream_health_check_offline{upstream="foreign-hk"} 1
upstream_health_check_offline{upstream="local-unbound"} 0
upstream_query_total{upstream="foreign-hk"} 11
upstream_query_total{upstream="local-unbound"} 7390
upstream_response_latency_millisecond_bucket{upstream="local-unbound",le="1"} 604
upstream_response_latency_millisecond_bucket{upstream="local-unbound",le="5"} 725
upstream_response_latency_millisecond_bucket{upstream="local-unbound",le="10"} 825
upstream_response_latency_millisecond_bucket{upstream="local-unbound",le="20"} 1047
upstream_response_latency_millisecond_bucket{upstream="local-unbound",le="50"} 1404
upstream_response_latency_millisecond_bucket{upstream="local-unbound",le="100"} 2209
upstream_response_latency_millisecond_bucket{upstream="local-unbound",le="200"} 4298
upstream_response_latency_millisecond_bucket{upstream="local-unbound",le="500"} 6561
upstream_response_latency_millisecond_bucket{upstream="local-unbound",le="1000"} 7106
upstream_response_latency_millisecond_bucket{upstream="local-unbound",le="2000"} 7267
upstream_response_latency_millisecond_bucket{upstream="local-unbound",le="5000"} 7352
upstream_response_latency_millisecond_bucket{upstream="local-unbound",le="+Inf"} 7359
upstream_response_latency_millisecond_sum{upstream="local-unbound"} 1958978
upstream_response_latency_millisecond_count{upstream="local-unbound"} 7359
`

func TestUpstreamRowsShowAnOfflineFallbackInsteadOfAnEmptyTable(t *testing.T) {
	rows := upstreamRows(parseMetrics(productionMetricsSample))
	if len(rows) != 2 {
		t.Fatalf("得到 %d 行上游，期望 2——这张表曾经从 Go 移植起就一直是空数组，"+
			"2026-10-01 香港递归离线 11.7 小时，面板上看不到任何迹象", len(rows))
	}
	hk, local := rows[0], rows[1]
	if hk["tag"] != "foreign-hk" || hk["online"] != false || hk["success_ratio"] != 0.0 {
		t.Errorf("foreign-hk = %v，期望离线、成功率 0", hk)
	}
	if local["online"] != true || local["avg_latency_ms"] != 266.2 || local["p95_latency_ms"] != 894.5 {
		t.Errorf("local-unbound = %v，期望在线、平均 266.2ms、p95 按直方图插值为 894.5ms", local)
	}
	if hk["p95_latency_ms"] != nil || hk["avg_latency_ms"] != nil {
		t.Errorf("没有延迟样本时应当给 null 让前端显示「—」，而不是 0ms：%v", hk)
	}
}

var mockUpstreamKey = regexp.MustCompile(`\b([a-z_][a-z0-9_]*):`)

func TestUpstreamRowsMatchTheMockAndWhatThePanelReads(t *testing.T) {
	backend := map[string]bool{}
	for key := range upstreamRows(parseMetrics(productionMetricsSample))[0] {
		backend[key] = true
	}

	mock, err := os.ReadFile("../../web/mock-api.js")
	if err != nil {
		t.Skipf("读不到 mock-api.js: %v", err)
	}
	text := string(mock)
	start := strings.Index(text, "const UPSTREAMS = [")
	end := strings.Index(text[start:], "];")
	mocked := map[string]bool{}
	for _, m := range mockUpstreamKey.FindAllStringSubmatch(text[start:start+end], -1) {
		mocked[m[1]] = true
	}
	if len(mocked) == 0 {
		t.Fatal("没从 mock 的 UPSTREAMS 里抽到任何字段，抽取规则失效")
	}
	diff := func(a, b map[string]bool) []string {
		var out []string
		for k := range a {
			if !b[k] {
				out = append(out, k)
			}
		}
		sort.Strings(out)
		return out
	}
	if only := diff(mocked, backend); len(only) > 0 {
		t.Errorf("mock 有而后端不产出的字段 %v——开发面板看着正常，上了生产这些格子就是空的", only)
	}
	if only := diff(backend, mocked); len(only) > 0 {
		t.Errorf("后端产出而 mock 没有的字段 %v——开发时看不到它们的样子", only)
	}

	body, found := functionBodies(panelScript(t))["renderOverviewUpstreams"]
	if !found {
		t.Fatal("panel.js 里没有 renderOverviewUpstreams 了")
	}
	for _, m := range regexp.MustCompile(`\bu\.([a-z_][a-z0-9_]*)`).FindAllStringSubmatch(body, -1) {
		if !backend[m[1]] {
			t.Errorf("前端读 u.%s，后端从不产出它", m[1])
		}
	}
}
