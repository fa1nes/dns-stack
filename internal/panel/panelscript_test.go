package panel

import (
	"os"
	"regexp"
	"testing"
)

var loaderStart = regexp.MustCompile(`(?m)^(?:async )?function ([A-Za-z0-9_]+)\(`)

func panelScript(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile("../../web/assets/panel.js")
	if err != nil {
		t.Skipf("读不到 panel.js: %v", err)
	}
	return string(body)
}

func functionBodies(script string) map[string]string {
	starts := loaderStart.FindAllStringSubmatchIndex(script, -1)
	bodies := map[string]string{}
	for i, m := range starts {
		name := script[m[2]:m[3]]
		end := len(script)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		bodies[name] = script[m[0]:end]
	}
	return bodies
}
