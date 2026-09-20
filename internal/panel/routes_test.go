package panel

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var routeRe = regexp.MustCompile(`mux\.HandleFunc\("([^"]+)"`)

var routesWithoutFrontendCaller = map[string]string{
	"/api/health": "install.sh 与 selfcheck 用它探活",
}

func frontendSources(t *testing.T) string {
	t.Helper()
	var all strings.Builder
	for _, path := range []string{"../../web/index.html", "../../web/login.html", "../../web/assets/panel.js"} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("读不到前端资源 %s: %v", path, err)
		}
		all.Write(body)
		all.WriteByte('\n')
	}
	return all.String()
}

func registeredRoutes(t *testing.T) []string {
	t.Helper()
	body, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	routes := []string{}
	for _, m := range routeRe.FindAllStringSubmatch(string(body), -1) {
		if m[1] != "/" {
			routes = append(routes, m[1])
		}
	}
	if len(routes) == 0 {
		t.Fatal("没从 server.go 里解析出任何路由，这个测试已经失去意义")
	}
	return routes
}

func TestEveryRouteHasSomethingThatCallsIt(t *testing.T) {
	frontend := frontendSources(t)
	for _, route := range registeredRoutes(t) {
		if reason, exempt := routesWithoutFrontendCaller[route]; exempt {
			if strings.Contains(frontend, route) {
				t.Errorf("%s 已在前端用上了(%s 这条豁免可以删)", route, reason)
			}
			continue
		}
		if !strings.Contains(frontend, strings.TrimSuffix(route, "/")) {
			t.Errorf("%s 注册了却没有任何前端调用它——要么前端漏接，要么这是死接口", route)
		}
	}
}
