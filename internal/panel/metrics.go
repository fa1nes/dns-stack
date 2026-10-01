package panel

import (
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/dns-stack/dns-stack/internal/metrics"
)

func metricScalar(s metrics.Set, name string) float64 {
	value, _ := s.Scalar(name)
	return value
}

func upstreamRows(parsed metrics.Set) []map[string]any {
	queries := parsed.ByLabel("upstream_query_total", "upstream")
	errs := parsed.ByLabel("upstream_err_total", "upstream")
	offline := parsed.ByLabel("upstream_health_check_offline", "upstream")
	latSum := parsed.ByLabel("upstream_response_latency_millisecond_sum", "upstream")
	latCount := parsed.ByLabel("upstream_response_latency_millisecond_count", "upstream")
	buckets := map[string][][2]float64{}
	for _, sample := range parsed["upstream_response_latency_millisecond_bucket"] {
		tag := sample.Labels["upstream"]
		le, err := strconv.ParseFloat(sample.Labels["le"], 64)
		if tag == "" || err != nil {
			continue
		}
		buckets[tag] = append(buckets[tag], [2]float64{le, sample.Value})
	}
	tags := make([]string, 0, len(queries))
	for tag := range queries {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	rows := make([]map[string]any, 0, len(tags))
	for _, tag := range tags {
		total, failed := queries[tag], errs[tag]
		row := map[string]any{"tag": tag, "online": offline[tag] == 0,
			"query_total": int(total), "err_total": int(failed),
			"success_ratio": nil, "avg_latency_ms": nil, "p95_latency_ms": nil}
		if total > 0 {
			row["success_ratio"] = roundTo((total-failed)*100/total, 2)
		}
		if latCount[tag] > 0 {
			row["avg_latency_ms"] = roundTo(latSum[tag]/latCount[tag], 1)
		}
		if p95, ok := histogramQuantile(buckets[tag], 0.95); ok {
			row["p95_latency_ms"] = roundTo(p95, 1)
		}
		rows = append(rows, row)
	}
	return rows
}

func histogramQuantile(buckets [][2]float64, q float64) (float64, bool) {
	sort.Slice(buckets, func(i, j int) bool { return buckets[i][0] < buckets[j][0] })
	if len(buckets) == 0 || buckets[len(buckets)-1][1] <= 0 {
		return 0, false
	}
	rank := q * buckets[len(buckets)-1][1]
	lower, below := 0.0, 0.0
	for _, b := range buckets {
		upper, count := b[0], b[1]
		if count >= rank {
			if math.IsInf(upper, 1) {
				return lower, true
			}
			if count == below {
				return upper, true
			}
			return lower + (upper-lower)*(rank-below)/(count-below), true
		}
		lower, below = upper, count
	}
	return lower, true
}

func parseUnboundStats(text string) map[string]float64 {
	out := map[string]float64{}
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		number, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err == nil {
			out[strings.TrimSpace(key)] = number
		}
	}
	if _, ok := out["total.num.queries"]; !ok {
		for key, value := range out {
			if strings.HasPrefix(key, "thread") {
				_, rest, _ := strings.Cut(key, ".")
				out["total."+rest] += value
			}
		}
	}
	return out
}
