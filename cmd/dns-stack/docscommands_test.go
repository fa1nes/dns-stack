package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func knownSubcommands(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	caseLabel := regexp.MustCompile(`case\s+("[^"]*"(?:\s*,\s*"[^"]*")*)\s*:`)
	quoted := regexp.MustCompile(`"([a-z][a-z0-9-]*)"`)
	known := map[string]bool{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range caseLabel.FindAllStringSubmatch(string(data), -1) {
			for _, q := range quoted.FindAllStringSubmatch(m[1], -1) {
				known[q[1]] = true
			}
		}
	}
	return known
}

func TestDocumentedCommandsExist(t *testing.T) {
	known := knownSubcommands(t)
	if !known["upgrade"] || !known["routing-data"] || !known["preflight"] {
		t.Fatalf("没能从源码里读出子命令表: %d 个", len(known))
	}
	mention := regexp.MustCompile(`dns-stack ([a-z][a-z0-9-]+)`)
	missing := map[string][]string{}
	err := filepath.WalkDir("../../site", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".")) {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range mention.FindAllStringSubmatch(string(data), -1) {
			if !known[m[1]] {
				missing[m[1]] = append(missing[m[1]], filepath.ToSlash(path))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(missing))
	for name := range missing {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Errorf("文档里写了 dns-stack %s，但二进制里没有这个子命令（%s）", name, strings.Join(missing[name], ", "))
	}
}
