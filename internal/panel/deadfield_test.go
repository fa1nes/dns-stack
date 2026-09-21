package panel

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func frontendText(t *testing.T) string {
	t.Helper()
	var all strings.Builder
	for _, path := range []string{"../../web/assets/panel.js", "../../web/index.html", "../../web/login.html"} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("读不到前端资源 %s: %v", path, err)
		}
		all.Write(body)
		all.WriteByte('\n')
	}
	return all.String()
}

func TestRulesInfoShipsNothingTheFrontendIgnores(t *testing.T) {
	dir := t.TempDir()
	server := New(Config{
		StateDir:   dir,
		ConfigPath: filepath.Join(dir, "config.env"),
		AuthPath:   filepath.Join(dir, "auth.json"),
		DBPath:     filepath.Join(dir, "collector.db"),
	})
	frontend := frontendText(t)
	for key := range server.rulesInfo() {
		if !regexp.MustCompile(`\b` + regexp.QuoteMeta(key) + `\b`).MatchString(frontend) {
			t.Errorf("/api/rules 每次都带上 %s，前端却从来不读它——"+
				"删掉一个功能之后，它在接口里的字段最容易留下来，"+
				"面板上看不见，只在流量和维护成本里", key)
		}
	}
}
