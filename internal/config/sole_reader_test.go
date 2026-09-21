package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var splitters = []string{`strings.Cut(line, "=")`, `strings.SplitN(line, "=", 2)`}

var allowedToSplitOnEquals = map[string]string{
	"internal/backup/migrate.go": "它是在改写 config.env，必须按原始行操作才能保住格式与注释",
	"internal/panel/server.go":   "它切的是 helper 的 KEY=VALUE 标准输出，不是 config.env",
}

func TestNobodyElseParsesConfigEnv(t *testing.T) {
	root := filepath.Join("..", "..")
	offenders := []string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() {
				switch info.Name() {
				case ".git", ".tmp", "node_modules", "web", ".deploy":
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "/internal/config/") {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		text := string(body)
		if !strings.Contains(text, "configPath") && !strings.Contains(text, "ConfigPath") &&
			!strings.Contains(text, "ConfigFile") && !strings.Contains(text, "config.env") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		if _, allowed := allowedToSplitOnEquals[filepath.ToSlash(rel)]; allowed {
			return nil
		}
		for _, splitter := range splitters {
			if strings.Contains(text, splitter) {
				offenders = append(offenders, filepath.ToSlash(rel))
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range offenders {
		t.Errorf("%s 自己在解析 config.env——用 config.Read/ReadKeys/Value。"+
			"手写解析器在引号、前导空格、等号两侧空格上各有各的规矩，"+
			"面板和 helper 对同一个 ROLE 读出不同的值时，角色闸门会一边放行一边拒绝", path)
	}
}
