package config

import (
	"os"
	"strings"
)

const DefaultPath = "/etc/dns-stack/config.env"

func ReadKeys(path string, keys ...string) map[string]string {
	if path == "" {
		path = DefaultPath
	}
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[k] = true
	}
	out := map[string]string{}
	body, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if want[k] {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}
