package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	DefaultBinaryPath = "/opt/dns-stack/bin/dns-stack-go"
	DefaultBackupDir  = "/var/backups/dns-stack"
	upgradeMinBytes   = 4 << 20
)

var UpgradeRestartable = []string{"dns-stack-helper", "dns-stack-panel", "mosproxy"}

type UpgradeOptions struct {
	Base      string
	Binary    string
	BackupDir string
	Current   string
	Restart   []string
	Check     bool
	Force     bool
	Now       func() time.Time
	VersionOf func(path string) (string, error)
	Systemctl func(ctx context.Context, args ...string) error
	Settle    time.Duration
}

type UpgradeResult struct {
	From     string
	To       string
	Changed  bool
	Backup   string
	Restart  []string
	Rollback bool
}

func ReleaseBase(cfg Config) string {
	if base := strings.TrimSpace(cfg.Value("DNS_STACK_BINARY_BASE")); base != "" {
		return strings.TrimRight(base, "/")
	}
	if repo := strings.TrimSpace(cfg.Value("DNS_STACK_BINARY_REPO")); repo != "" {
		return "https://github.com/" + repo + "/releases/download/binaries-latest"
	}
	return ""
}

func ParseRestart(list string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, raw := range strings.Split(list, ",") {
		unit := strings.TrimSuffix(strings.TrimSpace(raw), ".service")
		if unit == "" || seen[unit] {
			continue
		}
		allowed := false
		for _, known := range UpgradeRestartable {
			allowed = allowed || unit == known
		}
		if !allowed {
			return nil, fmt.Errorf("不能由 upgrade 重启 %s，可选：%s", unit, strings.Join(UpgradeRestartable, ", "))
		}
		seen[unit] = true
		out = append(out, unit)
	}
	ordered := []string{}
	for _, unit := range UpgradeRestartable {
		if seen[unit] {
			ordered = append(ordered, unit)
		}
	}
	return ordered, nil
}

func binaryVersion(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil {
		return "", fmt.Errorf("新二进制无法在本机执行：%w", err)
	}
	version := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "dns-stack"))
	if version == "" {
		return "", errors.New("新二进制没有报出版本号")
	}
	return version, nil
}

func systemctl(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s：%v %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func writeSidecar(binary string) error {
	sum, err := fileSHA256(binary)
	if err != nil {
		return err
	}
	return os.WriteFile(binary+".sha256", []byte(sum+"  "+filepath.Base(binary)+"\n"), 0o644)
}

func (o *UpgradeOptions) defaults() {
	if o.Binary == "" {
		o.Binary = DefaultBinaryPath
	}
	if o.BackupDir == "" {
		o.BackupDir = DefaultBackupDir
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.VersionOf == nil {
		o.VersionOf = binaryVersion
	}
	if o.Systemctl == nil {
		o.Systemctl = systemctl
	}
	if o.Settle == 0 {
		o.Settle = 3 * time.Second
	}
}

func Upgrade(ctx context.Context, rt *Runtime, opt UpgradeOptions) (UpgradeResult, error) {
	opt.defaults()
	res := UpgradeResult{From: opt.Current, Restart: opt.Restart}
	if opt.Base == "" {
		return res, errors.New("不知道从哪里下载：在 config.env 配 DNS_STACK_BINARY_REPO，或用 --base 指定 Release 地址")
	}
	name := "dns-stack-linux-" + runtime.GOARCH
	work, err := os.MkdirTemp(filepath.Dir(opt.Binary), ".upgrade-")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(work)

	sumPath := filepath.Join(work, name+".sha256")
	if _, err := rt.Fetch(ctx, fetchSpec{Kind: "校验和", URL: opt.Base + "/" + name + ".sha256", Dest: sumPath, MinBytes: 64}); err != nil {
		return res, fmt.Errorf("取不到 %s.sha256：%w", name, err)
	}
	raw, err := os.ReadFile(sumPath)
	if err != nil {
		return res, err
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 || len(fields[0]) != 64 {
		return res, fmt.Errorf("%s.sha256 内容不是校验和", name)
	}
	want := strings.ToLower(fields[0])

	staged := filepath.Join(work, name)
	verify := func(path string) error {
		got, err := fileSHA256(path)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("sha256 与 CI 记录不符（期望 %s，实际 %s）", want[:12], got[:12])
		}
		return nil
	}
	if _, err := rt.Fetch(ctx, fetchSpec{Kind: name, URL: opt.Base + "/" + name, Dest: staged, MinBytes: upgradeMinBytes, Verify: verify}); err != nil {
		return res, err
	}
	if err := os.Chmod(staged, 0o755); err != nil {
		return res, err
	}
	res.To, err = opt.VersionOf(staged)
	if err != nil {
		return res, err
	}
	if res.To == opt.Current && !opt.Force {
		return res, nil
	}
	if opt.Check {
		res.Changed = res.To != opt.Current
		return res, nil
	}

	if err := os.MkdirAll(opt.BackupDir, 0o755); err != nil {
		return res, err
	}
	res.Backup = filepath.Join(opt.BackupDir, "dns-stack-go.pre-"+opt.Now().Format("20060102150405"))
	if err := copyFile(opt.Binary, res.Backup, 0o755); err != nil {
		return res, fmt.Errorf("备份当前二进制失败：%w", err)
	}
	if err := os.Rename(staged, opt.Binary); err != nil {
		return res, fmt.Errorf("替换二进制失败：%w", err)
	}
	res.Changed = true
	_ = writeSidecar(opt.Binary)

	if err := restartAndCheck(ctx, opt); err != nil {
		res.Rollback = true
		if rerr := copyFile(res.Backup, opt.Binary, 0o755); rerr != nil {
			return res, fmt.Errorf("%v；回滚也失败了：%v（备份在 %s）", err, rerr, res.Backup)
		}
		_ = writeSidecar(opt.Binary)
		if rerr := restartAndCheck(ctx, opt); rerr != nil {
			return res, fmt.Errorf("%v；已换回旧二进制，但服务仍未恢复：%v", err, rerr)
		}
		return res, fmt.Errorf("%v；已换回旧二进制 %s", err, opt.Current)
	}
	return res, nil
}

func restartAndCheck(ctx context.Context, opt UpgradeOptions) error {
	for _, unit := range opt.Restart {
		if err := opt.Systemctl(ctx, "restart", unit+".service"); err != nil {
			return err
		}
	}
	if len(opt.Restart) == 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(opt.Settle):
	}
	for _, unit := range opt.Restart {
		if err := opt.Systemctl(ctx, "is-active", "--quiet", unit+".service"); err != nil {
			return fmt.Errorf("%s 重启后没有在运行", unit)
		}
	}
	return nil
}
