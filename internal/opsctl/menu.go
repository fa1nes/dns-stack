package opsctl

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"github.com/dns-stack/dns-stack/internal/stack"
)

type entry struct {
	label string
	run   func(*Ctl, context.Context) error
}

func prompt(c *Ctl, question string) string {
	fmt.Fprint(c.Out, question)
	line, err := bufio.NewReader(c.In).ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(line)
}

func cnMenu() []entry {
	return []entry{
		{"查看运行状态", func(c *Ctl, ctx context.Context) error { return c.Go(ctx, "status") }},
		{"执行健康检查", func(c *Ctl, ctx context.Context) error { return c.Go(ctx, "selfcheck") }},
		{"测试域名解析", func(c *Ctl, ctx context.Context) error {
			return c.TestDomain(ctx, prompt(c, "请输入要测试的域名: "), prompt(c, "客户端子网(可留空): "))
		}},
		{"同步最新规则", func(c *Ctl, ctx context.Context) error { return c.Sync(ctx, false) }},
		{"回滚上一版规则", (*Ctl).rollbackEntry},
		{"重载 DNS 服务", (*Ctl).reloadEntry},
		{"重启 DNS 服务", (*Ctl).restartEntry},
		{"查看运行日志", func(c *Ctl, ctx context.Context) error { return c.Logs(ctx, "mosproxy") }},
		{"立即备份", func(c *Ctl, ctx context.Context) error { return c.Go(ctx, "backup") }},
		{"导出迁移包", func(c *Ctl, ctx context.Context) error {
			return c.Go(ctx, "export", "--mode", orAsk(c, "导出模式(config/state/full): ", "full"))
		}},
		{"导入迁移包", func(c *Ctl, ctx context.Context) error {
			return c.Go(ctx, "import", prompt(c, "请输入迁移包路径: "))
		}},
		{"查看已有备份/导出包", func(c *Ctl, ctx context.Context) error { return c.ListPackages() }},
		{"检查 TLS 证书", (*Ctl).certCheckEntry},
		{"续签 TLS 证书", (*Ctl).certRenewEntry},
		{"查看管理面板信息", func(c *Ctl, ctx context.Context) error {
			fmt.Fprintln(c.Out, "面板地址: http://127.0.0.1:8080 (需通过 SSH 隧道或 WireGuard 访问)")
			return nil
		}},
		{"停止旧服务器服务", (*Ctl).migrationFinishEntry},
		{"采集 GFW 污染 IP", func(c *Ctl, ctx context.Context) error { return c.Go(ctx, "collect-polluted") }},
		{"查看递归出口分流", (*Ctl).routingStatusEntry},
		{"刷新递归分流数据", (*Ctl).routingRefreshEntry},
	}
}

func builderMenu() []entry {
	return []entry{
		{"查看运行状态", func(c *Ctl, ctx context.Context) error { return c.Go(ctx, "status") }},
		{"执行健康检查", func(c *Ctl, ctx context.Context) error { return c.Go(ctx, "selfcheck") }},
		{"拉取候选域名", (*Ctl).pullEntry},
		{"立即执行分类", func(c *Ctl, ctx context.Context) error { return c.Classify(ctx, "") }},
		{"查询指定域名分类", func(c *Ctl, ctx context.Context) error {
			return c.Classify(ctx, prompt(c, "请输入要查询的域名: "))
		}},
		{"生成 CN/GFW 规则", func(c *Ctl, ctx context.Context) error { return c.BuildRules(ctx, false) }},
		{"发布规则到 GitHub", (*Ctl).publishEntry},
		{"更新参考数据", (*Ctl).updateReferenceEntry},
		{"查看分类日志", func(c *Ctl, ctx context.Context) error { return c.Logs(ctx, "dns-stack-classify") }},
		{"立即备份", func(c *Ctl, ctx context.Context) error { return c.Go(ctx, "backup") }},
		{"导出迁移包", func(c *Ctl, ctx context.Context) error {
			return c.Go(ctx, "export", "--mode", orAsk(c, "导出模式(config/state/full): ", "full"))
		}},
		{"导入迁移包", func(c *Ctl, ctx context.Context) error {
			return c.Go(ctx, "import", prompt(c, "请输入迁移包路径: "))
		}},
		{"查看已有备份/导出包", func(c *Ctl, ctx context.Context) error { return c.ListPackages() }},
		{"查看管理面板信息", func(c *Ctl, ctx context.Context) error {
			fmt.Fprintln(c.Out, "面板地址: http://127.0.0.1:8080 (需通过 SSH 隧道或 WireGuard 访问)")
			return nil
		}},
		{"停止旧服务器服务", (*Ctl).migrationFinishEntry},
		{"一键重建规则(不发布)", (*Ctl).rebuildEntry},
	}
}

func (c *Ctl) rollbackEntry(ctx context.Context) error        { return c.Rollback(ctx) }
func (c *Ctl) reloadEntry(ctx context.Context) error          { return c.Reload(ctx) }
func (c *Ctl) restartEntry(ctx context.Context) error         { return c.Restart(ctx) }
func (c *Ctl) certCheckEntry(ctx context.Context) error       { return c.CertCheck(ctx) }
func (c *Ctl) certRenewEntry(ctx context.Context) error       { return c.CertRenew(ctx) }
func (c *Ctl) migrationFinishEntry(ctx context.Context) error { return c.MigrationFinish(ctx) }
func (c *Ctl) routingStatusEntry(ctx context.Context) error   { return c.RoutingStatus(ctx) }
func (c *Ctl) routingRefreshEntry(ctx context.Context) error  { return c.RoutingRefresh(ctx) }
func (c *Ctl) pullEntry(ctx context.Context) error            { return c.Pull(ctx) }
func (c *Ctl) publishEntry(ctx context.Context) error         { return c.Publish(ctx) }
func (c *Ctl) updateReferenceEntry(ctx context.Context) error { return c.UpdateReferenceData(ctx) }
func (c *Ctl) rebuildEntry(ctx context.Context) error         { return c.RebuildRules(ctx) }

func orAsk(c *Ctl, question, fallback string) string {
	if answer := prompt(c, question); answer != "" {
		return answer
	}
	return fallback
}

func (c *Ctl) Menu(ctx context.Context) error {
	role := c.Role()
	entries := builderMenu()
	title := "规则构建服务器"
	if role == stack.RoleCNResolver {
		entries = cnMenu()
		title = "国内 DNS 服务器"
	}
	for {
		fmt.Fprintln(c.Out, "========================================")
		fmt.Fprintln(c.Out, "        DNS Stack 中文管理工具")
		fmt.Fprintln(c.Out, "========================================")
		fmt.Fprintf(c.Out, "当前角色：%s\n", title)
		if c.unitActive(ctx, "unbound.service") {
			fmt.Fprintln(c.Out, "服务状态：运行正常")
		} else {
			fmt.Fprintln(c.Out, "服务状态：部分服务未运行")
		}
		fmt.Fprintln(c.Out)
		for i, item := range entries {
			fmt.Fprintf(c.Out, "%2d. %s\n", i+1, item.label)
		}
		fmt.Fprintln(c.Out, " 0. 退出")
		fmt.Fprintln(c.Out, "========================================")

		choice := prompt(c, "请输入选项: ")
		if choice == "0" {
			fmt.Fprintln(c.Out, "再见喵～")
			return nil
		}
		index := 0
		if _, err := fmt.Sscanf(choice, "%d", &index); err != nil || index < 1 || index > len(entries) {
			c.Warnf("无效选项")
			continue
		}
		if err := entries[index-1].run(c, ctx); err != nil {
			fmt.Fprintf(c.Out, "[错误] %v\n", err)
		}
		prompt(c, "\n按回车继续...")
	}
}
