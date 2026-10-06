package config

import (
	"os"
	"sort"
	"strings"

	"github.com/dns-stack/dns-stack/internal/statefile"
)

func Upsert(path string, values map[string]string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	done := map[string]bool{}
	for i, line := range lines {
		key, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		key = strings.TrimSpace(key)
		if value, wanted := values[key]; ok && wanted && !strings.HasPrefix(key, "#") {
			lines[i] = key + "=" + value
			done[key] = true
		}
	}
	missing := make([]string, 0, len(values))
	for key := range values {
		if !done[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	for _, key := range missing {
		lines = append(lines, key+"="+values[key])
	}
	mode := os.FileMode(0o640)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	return statefile.WriteAtomic(path, []byte(strings.Join(lines, "\n")+"\n"), mode)
}
