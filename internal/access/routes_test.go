package access

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

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
	if !reflect.DeepEqual(cn, []string{"example.cn", "sb.sb"}) || !reflect.DeepEqual(hk, []string{"google.com"}) {
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
