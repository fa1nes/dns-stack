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
}

func TestEveryExemptionStillCoversSomething(t *testing.T) {
	root := filepath.Join("..", "..")
	for rel, reason := range allowedToSplitOnEquals {
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Errorf("%s 在豁免名单里，但文件已经不存在了", rel)
			continue
		}
		covered := false
		for _, splitter := range splitters {
			if strings.Contains(string(body), splitter) {
				covered = true
			}
		}
		if !covered {
			t.Errorf("%s 被豁免的理由是「%s」，可它里面已经没有按等号切行的代码了——"+
				"代码搬走以后豁免还留在原地，下一个在这个文件里手写 config.env 解析器的人会被静默放行", rel, reason)
		}
	}
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
