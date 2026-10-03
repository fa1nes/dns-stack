package access

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestEditingAListKeepsTheNotesAroundIt(t *testing.T) {
	s := newStore(t)
	path := filepath.Join(s.StateDir, RouteCNFile)
	original := "# Apple：IP 注册在美国，归属库判不出来\napple.com\nicloud.com\n\n# 权威在境外但服务国内\niqiyi.com\n"
	if err := os.WriteFile(path, []byte(original), 0o664); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AddRoutes(RouteCN, []string{"sb.sb"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemoveRoutes(RouteCN, []string{"ICLOUD.com."}); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(path)
	want := "# Apple：IP 注册在美国，归属库判不出来\napple.com\n\n# 权威在境外但服务国内\niqiyi.com\nsb.sb\n"
	if string(body) != want {
		t.Fatalf("改名单把人写的说明和顺序一起抹掉了：\n%s", body)
	}
	if info, _ := os.Stat(path); runtime.GOOS != "windows" && info.Mode().Perm() != 0o664 {
		t.Fatalf("权限从 0664 变成了 %o", info.Mode().Perm())
	}
}

func TestADomainLivesInAtMostOneRouteList(t *testing.T) {
	s := newStore(t)
	if err := os.WriteFile(filepath.Join(s.StateDir, RouteHKFile), []byte("# 旧注释\nsb.sb\ngoogle.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	added, moved, err := s.AddRoutes(RouteCN, []string{"SB.sb.", "example.cn", "example.cn"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(added, []string{"sb.sb", "example.cn"}) || !reflect.DeepEqual(moved, []string{"sb.sb"}) {
		t.Fatalf("added=%v moved=%v", added, moved)
	}
	cn, _ := s.Routes(RouteCN)
	hk, _ := s.Routes(RouteHK)
	if !reflect.DeepEqual(cn, []string{"sb.sb", "example.cn"}) || !reflect.DeepEqual(hk, []string{"google.com"}) {
		t.Fatalf("同一个域名同时在两张名单里会让结果取决于规则顺序：cn=%v hk=%v", cn, hk)
	}

	added, moved, err = s.AddRoutes(RouteCN, []string{"sb.sb"})
	if err != nil || len(added) != 0 || len(moved) != 0 {
		t.Fatalf("重复加入不该改动文件：added=%v moved=%v err=%v", added, moved, err)
	}
	if _, _, err := s.AddRoutes(RouteHK, []string{"com"}); err == nil {
		t.Fatal("整个顶级域进名单会连带改写这个后缀下所有域名的解析路径，应当拒绝")
	}
	removed, err := s.RemoveRoutes(RouteCN, []string{"sb.sb", "absent.example"})
	if err != nil || !reflect.DeepEqual(removed, []string{"sb.sb"}) {
		t.Fatalf("removed=%v err=%v", removed, err)
	}
	if _, err := ParseRouteList("gfw"); err == nil {
		t.Fatal("只有 cn / hk 两张名单")
	}
	if list, err := ParseRouteList(" CN "); err != nil || list != RouteCN {
		t.Fatalf("命令行敲 CN 也该认得：%q %v", list, err)
	}
}
