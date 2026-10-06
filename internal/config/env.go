package config

import (
	"os"
	"strings"
)

const DefaultPath = "/etc/dns-stack/config.env"

func Read(path string) map[string]string {
	out := map[string]string{}
	each(path, func(key, value string) { out[key] = value })
	return out
}

func ReadKeys(path string, keys ...string) map[string]string {
	want := make(map[string]bool, len(keys))
	for _, key := range keys {
		want[key] = true
	}
	out := map[string]string{}
	each(path, func(key, value string) {
		if want[key] {
			out[key] = value
		}
	})
	return out
}

func Value(path, key string) string { return ReadKeys(path, key)[key] }

func each(path string, visit func(key, value string)) {
	if path == "" {
		path = DefaultPath
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			continue
		}
		visit(key, unquote(strings.TrimSpace(value)))
	}
}

func unquote(value string) string {
	if len(value) >= 2 {
		if quote := value[0]; quote == '"' || quote == '\'' {
			if value[len(value)-1] == quote {
				return value[1 : len(value)-1]
			}
		}
	}
	return value
}
