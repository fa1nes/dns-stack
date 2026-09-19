package classify

import (
	"strings"
	"testing"

	"github.com/dns-stack/dns-stack/internal/stack"
)

func TestPublishRefusesOnAnyRoleButTheBuilder(t *testing.T) {
	for _, role := range []string{stack.RoleCNResolver, "", "unknown", "GLOBAL-BUILDER"} {
		e := &Engine{Config: Config{
			Role:       role,
			Repository: "fa1nes/sing-box-rules",
			Branch:     "main",
			StateDir:   t.TempDir(),
		}}
		if err := e.EnsureRepo(); err == nil || !strings.Contains(err.Error(), "规则构建节点") {
			t.Errorf("EnsureRepo 在角色 %q 下应被拒绝，实际 %v", role, err)
		}
		if _, err := e.Publish(PublishOptions{}); err == nil ||
			!strings.Contains(err.Error(), "规则构建节点") {
			t.Errorf("Publish 在角色 %q 下应被拒绝，实际 %v", role, err)
		}
	}
}

func TestPublishGateLetsTheBuilderThrough(t *testing.T) {
	e := &Engine{Config: Config{Role: stack.RoleGlobalBuilder, StateDir: t.TempDir()}}
	if err := e.requireBuilder(); err != nil {
		t.Fatalf("构建节点被自己的闸门拦住了: %v", err)
	}
	e.Config.Repository = ""
	if err := e.EnsureRepo(); err == nil || !strings.Contains(err.Error(), "GITHUB_REPOSITORY") {
		t.Fatalf("构建节点应当越过角色闸门、走到后续校验，实际 %v", err)
	}
}
