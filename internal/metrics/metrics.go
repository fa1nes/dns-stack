package metrics

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const MosproxyURL = "http://127.0.0.1:8888/metrics"

type Sample struct {
	Labels map[string]string
	Value  float64
}

type Set map[string][]Sample

var line = regexp.MustCompile(`^([A-Za-z_:][A-Za-z0-9_:]*)(?:\{([^}]*)\})?\s+([^\s]+)$`)
var label = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)="((?:[^"\\]|\\.)*)"`)

func Parse(text string) Set {
	out := Set{}
	for _, raw := range strings.Split(text, "\n") {
		m := line.FindStringSubmatch(strings.TrimSpace(raw))
		if len(m) == 0 {
			continue
		}
		value, err := strconv.ParseFloat(m[3], 64)
		if err != nil {
			continue
		}
		labels := map[string]string{}
		for _, p := range label.FindAllStringSubmatch(m[2], -1) {
			labels[p[1]] = p[2]
		}
		out[m[1]] = append(out[m[1]], Sample{Labels: labels, Value: value})
	}
	return out
}

func (s Set) Scalar(name string) (float64, bool) {
	if values := s[name]; len(values) > 0 {
		return values[0].Value, true
	}
	return 0, false
}

func (s Set) ByLabel(name, key string) map[string]float64 {
	out := map[string]float64{}
	for _, sample := range s[name] {
		if value, ok := sample.Labels[key]; ok {
			out[value] = sample.Value
		}
	}
	return out
}

func (s Set) OfflineUpstreams() []string {
	var out []string
	for tag, offline := range s.ByLabel("upstream_health_check_offline", "upstream") {
		if offline != 0 {
			out = append(out, tag)
		}
	}
	sort.Strings(out)
	return out
}

func Fetch(ctx context.Context, url string) (Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("指标接口返回 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	return Parse(string(body)), nil
}
