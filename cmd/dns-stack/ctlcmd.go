package main

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/dns-stack/dns-stack/internal/opsctl"
)

func newCtl(args []string) (*opsctl.Ctl, []string) {
	ctl := opsctl.New()
	rest := make([]string, 0, len(args))
	for _, arg := range args {
		switch arg {
		case "--yes", "-y":
			ctl.AssumeYes = true
		case "--verbose":
		default:
			rest = append(rest, arg)
		}
	}
	if v := strings.TrimSpace(os.Getenv("DNS_STACK_STATE")); v != "" {
		ctl.StateDir = v
	}
	if v := strings.TrimSpace(os.Getenv("CONFIG_FILE")); v != "" {
		ctl.ConfigFile = v
	}
	if path, err := os.Executable(); err == nil {
		ctl.GoBin = path
	}
	return ctl, rest
}

func arg(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

func ctlDispatch(cmd string, raw []string) (bool, error) {
	ctl, args := newCtl(raw)
	ctx := context.Background()
	switch cmd {
	case "menu":
		return true, ctl.Menu(ctx)
	case "health":
		return true, cmdSelfCheck(nil)
	case "preflight", "check":
		return true, cmdSelfCheck([]string{"--full"})
	case "test":
		return true, ctl.TestDomain(ctx, arg(args, 0), arg(args, 1))
	case "diag":
		return true, ctl.TestDomain(ctx, arg(args, 0), arg(args, 1))
	case "sync":
		return true, ctl.Sync(ctx, hasFlag(args, "--force"))
	case "rollback":
		return true, ctl.Rollback(ctx)
	case "reload":
		return true, ctl.Reload(ctx)
	case "restart":
		return true, ctl.Restart(ctx)
	case "logs":
		return true, ctl.Logs(ctx, arg(args, 0))
	case "cert-check":
		return true, ctl.CertCheck(ctx)
	case "cert-renew":
		return true, ctl.CertRenew(ctx)
	case "routing-status":
		return true, ctl.RoutingStatus(ctx)
	case "routing-refresh":
		return true, ctl.RoutingRefresh(ctx)
	case "pull":
		return true, ctl.Pull(ctx)
	case "verify-rules":
		return true, ctl.VerifyRules(ctx, args)
	case "build-rules":
		return true, ctl.BuildRules(ctx, hasFlag(args, "--force"))
	case "publish":
		return true, ctl.Publish(ctx)
	case "update-cn-ip":
		return true, ctl.UpdateReferenceData(ctx)
	case "classify-authority":
		return true, ctl.ClassifyAuthority(ctx, args)
	case "rebuild-rules":
		return true, ctl.RebuildRules(ctx)
	case "panel-password":
		return true, ctl.PanelPassword(ctx)
	case "panel-2fa-reset":
		return true, ctl.PanelResetTOTP(ctx)
	case "clear-audit":
		return true, ctl.ClearAudit(ctx)
	case "clear-domains":
		return true, ctl.ClearDomains(ctx, ctlArgOr(arg(args, 0), "7"))
	case "purge-legacy":
		return true, ctl.PurgeLegacy(ctx)
	case "set-arch-epoch":
		return true, ctl.SetArchEpoch(ctx, arg(args, 0))
	case "vacuum-logs":
		return true, ctl.VacuumLogs(ctx, arg(args, 0))
	case "list-packages":
		return true, ctl.ListPackages()
	case "migration-finish":
		return true, ctl.MigrationFinish(ctx)
	case "migrate":
		return true, ctl.Migrate(ctx, parseMigrateOptions(args))
	case "wg-peer":
		return true, ctl.WGPeer(ctx, parseWGPeerOptions(args))
	}
	return false, nil
}

func parseMigrateOptions(args []string) opsctl.MigrateOptions {
	opt := opsctl.MigrateOptions{Port: 22}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--port":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 {
					opt.Port = n
				}
				i++
			}
		case "--identity":
			if i+1 < len(args) {
				opt.Identity = args[i+1]
				i++
			}
		case "--dry-run":
			opt.DryRun = true
		default:
			if opt.Target == "" {
				opt.Target = args[i]
			}
		}
	}
	return opt
}

func parseWGPeerOptions(args []string) opsctl.WGPeerOptions {
	opt := opsctl.WGPeerOptions{Port: 22}
	take := func(i int) (string, bool) {
		if i+1 < len(args) {
			return args[i+1], true
		}
		return "", false
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--port":
			if v, ok := take(i); ok {
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
					opt.Port = n
				}
				i++
			}
		case "--identity":
			if v, ok := take(i); ok {
				opt.Identity, i = v, i+1
			}
		case "--cn-ip":
			if v, ok := take(i); ok {
				opt.CNAddr, i = v, i+1
			}
		case "--hk-ip":
			if v, ok := take(i); ok {
				opt.HKAddr, i = v, i+1
			}
		case "--endpoint":
			if v, ok := take(i); ok {
				opt.Endpoint, i = v, i+1
			}
		case "--apply":
			opt.Apply = true
		case "--dry-run":
			opt.Apply = false
		default:
			if opt.Target == "" {
				opt.Target = args[i]
			}
		}
	}
	return opt
}

func ctlArgOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func ctlUsage() string {
	return `
运维命令:
  menu            交互式菜单
  health          完整健康检查(等同 selfcheck)
  preflight       投产校验(selfcheck --full：追加入口探针、权限、conntrack、面板鉴权)
  test <域名> [子网]  解析一个域名并解释出口分流、CDN 归属与就近结果
  sync [--force]  立即同步规则包与 CDN 规则集
  rollback        回滚到上一版规则包
  reload          重载 mosproxy 域名表(及 Unbound)
  restart         重启 mosproxy 与 Unbound
  logs [单元]     查看最近 100 行日志
  cert-check      检查 TLS 证书
  cert-renew      续签 TLS 证书
  routing-status  查看递归出口分流现状
  routing-refresh 重建全部分流数据
  backup / export / import / verify / list-packages   备份与迁移包
  migrate <root@新机> [--port N] [--identity 私钥] [--dry-run]  一键迁移到新服务器
  wg-peer <root@HK> [--apply]  把本机注册成 HK 的 WireGuard peer(默认预演)
  migration-finish  停止旧服务器上的服务(不删数据)
  db-migrate      备份数据库并按当前 schema 就地迁移
  panel-password / panel-2fa-reset           面板凭据
  clear-audit / clear-domains / purge-legacy / vacuum-logs / set-arch-epoch
  pull / classify / build-rules / publish / rebuild-rules / verify-rules
  update-cn-ip / classify-authority          (规则构建节点)
`
}
