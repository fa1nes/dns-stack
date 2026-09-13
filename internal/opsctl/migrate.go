package opsctl

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	incomingDir     = "/root/dns-stack-migrate-incoming"
	minRemoteFreeKB = 2097152
	stackRoot       = "/opt/dns-stack/dns-stack"
)

var shippedItems = []string{
	"install.sh", "config.example.env", "versions.lock",
	"systemd", "unbound", "mosproxy", "rules", "docs",
}

type MigrateOptions struct {
	Target   string
	Port     int
	Identity string
	DryRun   bool
	Root     string
}

func (c *Ctl) sshArgs(opt MigrateOptions) []string {
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=accept-new",
	}
	if opt.Identity != "" {
		args = append(args, "-i", opt.Identity)
	}
	return args
}

func (c *Ctl) sshCapture(ctx context.Context, opt MigrateOptions, command string) (string, error) {
	args := append(c.sshArgs(opt), "-p", strconv.Itoa(opt.Port), opt.Target, command)
	out, err := exec.CommandContext(ctx, "ssh", args...).Output()
	return strings.TrimSpace(string(out)), err
}

func (c *Ctl) sshRun(ctx context.Context, opt MigrateOptions, command string) error {
	args := append(c.sshArgs(opt), "-p", strconv.Itoa(opt.Port), opt.Target, command)
	return c.Run(ctx, "ssh", args...)
}

func (c *Ctl) scp(ctx context.Context, opt MigrateOptions, local, remote string) error {
	args := append(c.sshArgs(opt), "-P", strconv.Itoa(opt.Port), local, opt.Target+":"+remote)
	return c.Run(ctx, "scp", args...)
}

func (c *Ctl) Migrate(ctx context.Context, opt MigrateOptions) error {
	if opt.Target == "" {
		return fmt.Errorf("用法: dns-stack migrate root@新服务器IP [--port 22] [--identity 私钥路径] [--dry-run]")
	}
	if opt.Port == 0 {
		opt.Port = 22
	}
	if opt.Root == "" {
		opt.Root = stackRoot
	}
	role := c.Role()
	if role == "unknown" {
		return fmt.Errorf("读不到本机角色(检查 %s 里的 ROLE)，无法确定目标机该装成什么角色", c.ConfigFile)
	}

	fmt.Fprintln(c.Out, "[1/10] 正在检查目标服务器连接...")
	if _, err := c.sshCapture(ctx, opt, "echo ok"); err != nil {
		return fmt.Errorf("无法通过 SSH 连接到 %s(端口 %d): %w", opt.Target, opt.Port, err)
	}
	c.Okf("SSH 连接正常")

	fmt.Fprintln(c.Out, "[2/10] 正在检查目标系统兼容性...")
	remoteOS, _ := c.sshCapture(ctx, opt, `. /etc/os-release; echo "$ID"`)
	remoteArch, _ := c.sshCapture(ctx, opt, "uname -m")
	if remoteOS != "debian" && remoteOS != "ubuntu" {
		return fmt.Errorf("目标系统不是 Debian/Ubuntu(检测到: %s)", remoteOS)
	}
	localArch := localMachineArch()
	if remoteArch != localArch {
		c.Warnf("架构不一致：本机 %s，目标 %s——数据库和二进制可能不兼容", localArch, remoteArch)
		if !opt.DryRun {
			return fmt.Errorf("架构不兼容，中止迁移(如确认要继续，请人工介入)")
		}
	}
	c.Okf("系统: %s / 架构: %s", remoteOS, remoteArch)

	fmt.Fprintln(c.Out, "[3/10] 正在检查磁盘空间...")
	availText, _ := c.sshCapture(ctx, opt, `df -Pk / | tail -1 | awk '{print $4}'`)
	avail, _ := strconv.Atoi(availText)
	if avail < minRemoteFreeKB {
		return fmt.Errorf("目标服务器可用空间不足 2GB(实得 %dMB)", avail/1024)
	}
	c.Okf("目标可用空间: %dMB", avail/1024)

	fmt.Fprintln(c.Out, "[4/10] 正在检查端口占用...")
	ports, _ := c.sshCapture(ctx, opt, `ss -tlnH 2>/dev/null | awk '{print $4}' | grep -oE '[0-9]+$' | sort -u`)
	for _, want := range []string{"5335", "8080"} {
		for _, line := range strings.Split(ports, "\n") {
			if strings.TrimSpace(line) == want {
				c.Warnf("目标服务器端口 %s 已被占用，可能与 dns-stack 冲突", want)
			}
		}
	}
	c.Okf("端口检查完成(仅提示，不阻断)")

	fmt.Fprintln(c.Out, "[5/10] 正在检查目标是否已有 DNS Stack...")
	if _, err := c.sshCapture(ctx, opt, "test -f /etc/dns-stack/config.env"); err == nil {
		return fmt.Errorf("目标服务器已存在 /etc/dns-stack/config.env，为避免覆盖数据，请先手动确认后再迁移")
	}
	c.Okf("目标是全新环境")

	if opt.DryRun {
		fmt.Fprintln(c.Out)
		fmt.Fprintln(c.Out, "--dry-run 模式：以上检查全部完成，不会修改目标服务器任何内容。")
		return nil
	}

	fmt.Fprintln(c.Out, "[6/10] 正在创建旧服务器一致性备份(含机密，age 加密)...")
	pkg, err := c.captureBackup(ctx)
	if err != nil {
		return err
	}
	c.Okf("迁移包: %s", pkg)

	fmt.Fprintln(c.Out, "[7/10] 正在传输迁移包与安装资源...")
	if err := c.sshRun(ctx, opt, "mkdir -p "+incomingDir+"/dns-stack/bin"); err != nil {
		return err
	}
	if err := c.scp(ctx, opt, pkg, incomingDir+"/"); err != nil {
		return fmt.Errorf("迁移包传输失败: %w", err)
	}
	if err := c.shipInstallTree(ctx, opt); err != nil {
		return err
	}
	if err := c.scp(ctx, opt, c.GoBin,
		fmt.Sprintf("%s/dns-stack/bin/dns-stack-linux-%s", incomingDir, goArchOf(localArch))); err != nil {
		return fmt.Errorf("Go 二进制传输失败: %w", err)
	}
	c.Okf("已附带本机正在运行的 Go 二进制，目标机无需联网下载也不会在本地编译")
	c.shipMosproxy(ctx, opt)
	c.Okf("传输完成")

	fmt.Fprintln(c.Out, "[8/10] 目标服务器安装 DNS Stack...")
	if err := c.sshRun(ctx, opt, fmt.Sprintf(
		"mkdir -p /etc/dns-stack && printf 'ROLE=%%s\\n' '%s' > /etc/dns-stack/config.env", role)); err != nil {
		return fmt.Errorf("目标机写入角色失败: %w", err)
	}
	if err := c.sshRun(ctx, opt, fmt.Sprintf(
		"chmod +x %s/dns-stack/install.sh && cd %s/dns-stack && bash install.sh </dev/null",
		incomingDir, incomingDir)); err != nil {
		return fmt.Errorf("目标机 install.sh 执行失败，请登录目标机查看输出后重试(数据尚未导入，旧机未受影响): %w", err)
	}
	c.Okf("目标服务器环境安装完成")

	fmt.Fprintln(c.Out, "[9/10] 在目标服务器校验并导入数据...")
	remotePkg := incomingDir + "/" + filepath.Base(pkg)
	if err := c.sshRun(ctx, opt, "dns-stack verify "+remotePkg); err != nil {
		return fmt.Errorf("迁移包在目标机校验失败，已中止导入: %w", err)
	}
	if err := c.sshRun(ctx, opt, "dns-stack import "+remotePkg); err != nil {
		return fmt.Errorf("目标机导入失败，请登录目标机执行 dns-stack health 查看状态: %w", err)
	}
	c.Okf("数据导入完成")

	fmt.Fprintln(c.Out, "[10/10] 目标服务器健康检查...")
	if err := c.sshRun(ctx, opt, "dns-stack health"); err != nil {
		c.Warnf("目标服务器健康检查未通过，请登录排查后再切流量")
	} else {
		c.Okf("目标服务器健康检查通过")
	}

	fmt.Fprintln(c.Out)
	fmt.Fprintln(c.Out, "旧服务器仍然保持运行，尚未停止或删除。")
	fmt.Fprintln(c.Out, "恢复过来的配置里含有**原服务器**的地址与路径，切流量前请在目标机确认：")
	fmt.Fprintln(c.Out, "  - /etc/dns-stack/config.env 里的 PUBLIC_IPV4 等需要改成新服务器的地址")
	fmt.Fprintln(c.Out, "  - TLS 证书需要按新地址重新签发: sudo dns-stack cert-renew")
	fmt.Fprintln(c.Out, "  - WireGuard 隧道需要在新机与 HK 重新对接")
	fmt.Fprintln(c.Out)
	fmt.Fprintln(c.Out, "确认新服务器稳定后，在旧服务器执行: sudo dns-stack migration-finish")
	return nil
}

func (c *Ctl) captureBackup(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, c.GoBin, "backup", "--include-secrets")
	cmd.Stderr = c.Out
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("备份失败: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	pkg := strings.TrimSpace(lines[len(lines)-1])
	if info, err := os.Stat(pkg); err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("备份失败：命令输出的路径不是文件(%q)", pkg)
	}
	return pkg, nil
}

func (c *Ctl) shipInstallTree(ctx context.Context, opt MigrateOptions) error {
	var missing []string
	for _, item := range shippedItems {
		if _, err := os.Stat(filepath.Join(opt.Root, item)); err != nil {
			missing = append(missing, item)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("安装资源不完整(缺 %s): %s\n   请先在本机用完整的项目目录重跑一次 install.sh 补齐，再执行迁移",
			strings.Join(missing, " "), opt.Root)
	}
	args := append(c.sshArgs(opt), "-p", strconv.Itoa(opt.Port), opt.Target,
		"tar -C "+incomingDir+"/dns-stack -x")
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stderr = c.Out
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	tw := tar.NewWriter(stdin)
	walkErr := writeTree(tw, opt.Root, shippedItems)
	closeErr := tw.Close()
	stdin.Close()
	waitErr := cmd.Wait()
	for _, err := range []error{walkErr, closeErr, waitErr} {
		if err != nil {
			return fmt.Errorf("安装资源传输失败: %w", err)
		}
	}
	return nil
}

func writeTree(tw *tar.Writer, root string, items []string) error {
	for _, item := range items {
		base := filepath.Join(root, item)
		if err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			hdr, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			hdr.Name = filepath.ToSlash(rel)
			if d.IsDir() {
				hdr.Name += "/"
			}
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(tw, f)
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}

func (c *Ctl) shipMosproxy(ctx context.Context, opt MigrateOptions) {
	binary := "/opt/dns-stack/bin/mosproxy"
	buildID, err := os.ReadFile(binary + ".build-id")
	if err != nil {
		return
	}
	version := strings.TrimSpace(string(buildID))
	if version == "" {
		c.Warnf("本机 mosproxy 缺少版本指纹，未附带；目标机会从 Release 拉最新版")
		return
	}
	for _, name := range []string{binary, binary + ".sha256", binary + ".build-id"} {
		if err := c.scp(ctx, opt, name, incomingDir+"/dns-stack/bin/"); err != nil {
			c.Warnf("mosproxy 产物传输失败，目标机会从 Release 拉最新版: %v", err)
			return
		}
	}
	c.Okf("已附带本机的 mosproxy 二进制(%s)", version)
}

func localMachineArch() string {
	if out, err := exec.Command("uname", "-m").Output(); err == nil {
		if v := strings.TrimSpace(string(out)); v != "" {
			return v
		}
	}
	return runtime.GOARCH
}

func goArchOf(machine string) string {
	switch machine {
	case "aarch64", "arm64":
		return "arm64"
	default:
		return "amd64"
	}
}
