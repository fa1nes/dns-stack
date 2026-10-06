package domain

import (
	"fmt"
	"os"
	"strings"
)

const (
	icannBegin = "===BEGIN ICANN DOMAINS==="
	icannEnd   = "===END ICANN DOMAINS==="
)

var DefaultPSLPaths = []string{
	"/var/lib/dns-stack/reference/public_suffix_list.dat",
	"/var/lib/dns-stack/psl-data/public_suffix_list.dat",
	"/usr/share/publicsuffix/public_suffix_list.dat",
}

type PSL struct {
	rules      map[string]struct{}
	wildcards  map[string]struct{}
	exceptions map[string]struct{}
	Source     string
}

func ParsePSL(text, source string) *PSL {
	p := &PSL{
		rules:      make(map[string]struct{}),
		wildcards:  make(map[string]struct{}),
		exceptions: make(map[string]struct{}),
		Source:     source,
	}
	hasMarker := strings.Contains(text, icannBegin)
	inside := !hasMarker
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "//") {
			if strings.Contains(line, icannBegin) {
				inside = true
			} else if strings.Contains(line, icannEnd) {
				inside = false
			}
			continue
		}
		if line == "" || !inside {
			continue
		}
		switch {
		case strings.HasPrefix(line, "!"):
			p.exceptions[Normalize(line[1:])] = struct{}{}
		case strings.HasPrefix(line, "*."):
			p.wildcards[Normalize(line[2:])] = struct{}{}
		default:
			p.rules[Normalize(line)] = struct{}{}
		}
	}
	return p
}

func (p *PSL) Len() int {
	if p == nil {
		return 0
	}
	return len(p.rules) + len(p.wildcards)
}

func (p *PSL) IsPublicSuffix(name string) bool {
	if p == nil {
		return false
	}
	name = Normalize(name)
	if name == "" {
		return false
	}
	if _, ok := p.exceptions[name]; ok {
		return false
	}
	if _, ok := p.rules[name]; ok {
		return true
	}
	_, parent, found := strings.Cut(name, ".")
	if !found || parent == "" {
		return false
	}
	_, ok := p.wildcards[parent]
	return ok
}

func LoadPSL(paths []string) (*PSL, string) {
	if paths == nil {
		if configured := strings.TrimSpace(os.Getenv("PSL_FILE")); configured != "" {
			paths = append([]string{configured}, DefaultPSLPaths...)
		} else {
			paths = DefaultPSLPaths
		}
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		psl := ParsePSL(string(data), path)
		if psl.Len() < 100 {
			continue
		}
		return psl, fmt.Sprintf("PSL 来自 %s（%d 条规则）", path, psl.Len())
	}
	return nil, fmt.Sprintf("未找到 Public Suffix List，退回内置兜底判据（无点单段名 + %d 个常见二级后缀）", len(fallbackPublicSuffixes))
}
