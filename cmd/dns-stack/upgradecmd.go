package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/dns-stack/dns-stack/internal/pipeline"
	"github.com/dns-stack/dns-stack/internal/stack"
	"github.com/dns-stack/dns-stack/internal/statefile"
)

const upgradeLock = "/run/lock/dns-stack-upgrade.lock"

func cmdUpgrade(args []string) error {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	state := fs.String("state", envOr("STATE_DIR", pipeline.DefaultStateDir), "状态目录")
	conf := fs.String("config", envOr("CONFIG_FILE", pipeline.DefaultConfigFile), "配置文件")
	base := fs.String("base", "", "Release 下载地址（默认按 config.env 的 DNS_STACK_BINARY_BASE 或 DNS_STACK_BINARY_REPO 拼出 binaries-latest）")
	restart := fs.String("restart", "dns-stack-helper,dns-stack-panel", "换好后重启哪些服务，逗号分隔；mosproxy 重启时解析中断约 0.1 秒、内存缓存清空，要用时显式写上")
	check := fs.Bool("check", false, "只下载并核对新版本号，不替换")
	force := fs.Bool("force", false, "版本相同也重新安装")
	mosproxy := fs.Bool("mosproxy", false, "升级 mosproxy（取 versions.lock 里那个 fork 的最新 Release），换好后重启它并用 DoH 自检；解析会中断约 0.1 秒")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *mosproxy {
		restartSet := false
		fs.Visit(func(f *flag.Flag) { restartSet = restartSet || f.Name == "restart" })
		if !restartSet {
			*restart = "mosproxy"
		}
	}
	cfg := pipeline.LoadConfig(*state, *conf)
	if strings.TrimSpace(cfg.Value("ROLE")) == stack.RoleOffshore {
		return errors.New("香港节点不走 upgrade：改动写进 install-hk.sh，在 HK 上整体运行一遍")
	}
	units, err := pipeline.ParseRestart(*restart)
	if err != nil {
		return err
	}
	if os.Geteuid() > 0 {
		return errors.New("需要 root：要替换 " + pipeline.DefaultBinaryPath + " 并重启服务")
	}
	unlock, err := statefile.TryLock(upgradeLock)
	if errors.Is(err, statefile.ErrLocked) {
		return errors.New("另一个 upgrade 正在进行")
	}
	if err != nil {
		return err
	}
	defer unlock()

	baseURL := strings.TrimRight(strings.TrimSpace(*base), "/")
	opt := pipeline.UpgradeOptions{Current: version, Restart: units, Check: *check, Force: *force}
	if *mosproxy {
		if baseURL == "" {
			repo, err := mosproxyRepo(cfg)
			if err != nil {
				return err
			}
			baseURL = "https://github.com/" + repo + "/releases/latest/download"
		}
		current, err := pipeline.MosproxyVersion(pipeline.MosproxyBinary)
		if err != nil {
			return err
		}
		opt.Current, opt.Binary, opt.Asset = current, pipeline.MosproxyBinary, "mosproxy-linux-"+runtime.GOARCH
		opt.BuildID, opt.VersionOf, opt.Backup = true, pipeline.MosproxyVersion, pipeline.MosproxyBackupName
		opt.Probe = dohProbe
	} else if baseURL == "" {
		baseURL = pipeline.ReleaseBase(cfg)
	}
	opt.Base = baseURL
	rt := pipeline.NewRuntime(cfg, os.Stdout)
	fmt.Printf("[信息] 当前版本 %s，从 %s 取最新构建\n", opt.Current, baseURL)
	res, err := pipeline.Upgrade(context.Background(), rt, opt)
	version := opt.Current
	switch {
	case err != nil:
		if res.Rollback {
			fmt.Printf("[失败] 升级到 %s 后服务没起来，已换回 %s\n", res.To, version)
		}
		return err
	case !res.Changed:
		fmt.Printf("[成功] 已是最新版本 %s\n", res.To)
	case *check:
		fmt.Printf("[信息] 有新版本：%s → %s（去掉 --check 即升级）\n", version, res.To)
	default:
		fmt.Printf("[成功] %s → %s；旧二进制备份在 %s\n", version, res.To, res.Backup)
		if len(units) > 0 {
			fmt.Printf("[信息] 已重启并确认在运行：%s\n", strings.Join(units, "、"))
		}
		if !*mosproxy && !strings.Contains(*restart, "mosproxy") {
			fmt.Println("[信息] 查询采集器跑在 mosproxy.service 里，仍是旧代码；下次重启 mosproxy 时生效（需要立刻生效就 --restart 加上 mosproxy：解析中断约 0.1 秒，内存缓存清空）")
		}
	}
	return nil
}

func mosproxyRepo(cfg pipeline.Config) (string, error) {
	if repo := strings.TrimSpace(cfg.Value("MOSPROXY_REPO")); repo != "" {
		return repo, nil
	}
	data, err := os.ReadFile("/opt/dns-stack/dns-stack/versions.lock")
	if err != nil {
		return "", errors.New("不知道 mosproxy 从哪个仓库下载：config.env 配 MOSPROXY_REPO，或重跑 install.sh 补齐 versions.lock")
	}
	var lock struct {
		Mosproxy struct {
			Repo string `json:"repo"`
		} `json:"mosproxy"`
	}
	if err := json.Unmarshal(data, &lock); err != nil || !strings.Contains(lock.Mosproxy.Repo, "/") {
		return "", errors.New("versions.lock 里没有 mosproxy.repo")
	}
	return lock.Mosproxy.Repo, nil
}

func dohProbe(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, selfBinary(), "doh-probe").Output()
	if err != nil || strings.TrimSpace(string(out)) != "ok" {
		return errors.New("DoH 自检没有回 ok")
	}
	return nil
}
