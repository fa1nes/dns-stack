package panel

import (
	"regexp"
	"strconv"
	"strings"
)

type metricSample struct {
	labels map[string]string
	value  float64
}

var metricLine = regexp.MustCompile(`^([A-Za-z_:][A-Za-z0-9_:]*)(?:\{([^}]*)\})?\s+([^\s]+)$`)
var metricLabel = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)="((?:[^"\\]|\\.)*)"`)

func parseMetrics(text string) map[string][]metricSample {
	out := map[string][]metricSample{}
	for _, line := range strings.Split(text, "\n") {
		m := metricLine.FindStringSubmatch(strings.TrimSpace(line))
		if len(m) == 0 {
			continue
		}
		value, err := strconv.ParseFloat(m[3], 64)
		if err != nil {
			continue
		}
		labels := map[string]string{}
		for _, p := range metricLabel.FindAllStringSubmatch(m[2], -1) {
			labels[p[1]] = p[2]
		}
		out[m[1]] = append(out[m[1]], metricSample{labels: labels, value: value})
	}
	return out
}

func metricScalar(parsed map[string][]metricSample, name string) float64 {
	if values := parsed[name]; len(values) > 0 {
		return values[0].value
	}
	return 0
}

func metricByLabel(parsed map[string][]metricSample, name, label string) map[string]float64 {
	out := map[string]float64{}
	for _, sample := range parsed[name] {
		if value, ok := sample.labels[label]; ok {
			out[value] = sample.value
		}
	}
	return out
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
