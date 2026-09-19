package opsctl

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dns-stack/dns-stack/internal/helper"
	"github.com/dns-stack/dns-stack/internal/stack"
)

var builderOnlyCommands = map[string]func(*Ctl, context.Context) error{
	"pull_candidates":       func(c *Ctl, ctx context.Context) error { return c.Pull(ctx) },
	"classify_start":        func(c *Ctl, ctx context.Context) error { return c.Classify(ctx, "") },
	"classify_domain":       func(c *Ctl, ctx context.Context) error { return c.Classify(ctx, "example.com") },
	"classify_authority":    func(c *Ctl, ctx context.Context) error { return c.ClassifyAuthority(ctx, nil) },
	"build_rules":           func(c *Ctl, ctx context.Context) error { return c.BuildRules(ctx, false) },
	"rebuild_rules":         func(c *Ctl, ctx context.Context) error { return c.RebuildRules(ctx) },
	"publish_github":        func(c *Ctl, ctx context.Context) error { return c.Publish(ctx) },
	"update_reference_data": func(c *Ctl, ctx context.Context) error { return c.UpdateReferenceData(ctx) },
}

func ctlWithRole(t *testing.T, role string) *Ctl {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.env")
	if err := os.WriteFile(path, []byte("ROLE="+role+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Ctl{
		StateDir:   t.TempDir(),
		ConfigFile: path,
		GoBin:      filepath.Join(t.TempDir(), "dns-stack-that-does-not-exist"),
		Out:        &bytes.Buffer{},
		In:         strings.NewReader(""),
	}
}

func TestBuilderOnlyCommandsRefuseOnTheResolverNode(t *testing.T) {
	ctx := context.Background()
	for _, role := range []string{stack.RoleCNResolver, "unknown"} {
		ctl := ctlWithRole(t, role)
		for op, call := range builderOnlyCommands {
			err := call(ctl, ctx)
			if err == nil {
				t.Errorf("角色 %s 执行 %s 没有被拒绝——国内节点可以直接绕过面板推 GitHub / 跑构建", role, op)
				continue
			}
			if !strings.Contains(err.Error(), "规则构建节点") {
				t.Errorf("角色 %s 执行 %s 的失败原因不是角色闸门，而是 %v——"+
					"闸门没拦住，只是碰巧在后面失败了", role, op, err)
			}
		}
	}
}

func TestEveryBuilderGatedHelperOpHasAGatedCLICounterpart(t *testing.T) {
	for op, want := range helper.RoleOps {
		if want != stack.RoleGlobalBuilder {
			continue
		}
		if _, covered := builderOnlyCommands[op]; !covered {
			t.Errorf("helper 只允许构建节点执行 %s，但本测试没有覆盖对应的 CLI 入口——"+
				"面板拦得住，SSH 上去直接跑 dns-stack 就拦不住", op)
		}
	}
}
