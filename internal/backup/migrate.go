package backup

import (
	"archive/tar"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var preservedConfigKeys = map[string]bool{"PUBLIC_IPV4": true, "PUBLIC_IPV6": true}

func (c Config) Export(ctx context.Context, mode string, includeLogs bool) (string, error) {
	switch mode {
	case ModeConfig, ModeState, ModeFull:
	default:
		return "", fmt.Errorf("导出模式必须是 config、state 或 full")
	}
	includeSecrets := mode == ModeFull
	if err := c.CheckDiskSpace(ctx); err != nil {
		return "", err
	}
	if err := os.MkdirAll(c.ExportDir, 0o755); err != nil {
		return "", err
	}
	work, err := os.MkdirTemp("", "dns-stack-export-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)
	const root = "dns-stack-export"
	dest := filepath.Join(work, root)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return "", err
	}

	c.logf("[信息] 正在收集配置和状态(模式: %s)...", mode)
	if err := c.CollectPayload(ctx, dest, mode, includeSecrets, includeLogs); err != nil {
		return "", err
	}
	c.logf("[信息] 正在生成 manifest.json...")
	if err := c.WriteManifest(dest, mode, includeSecrets, includeLogs); err != nil {
		return "", err
	}
	c.logf("[信息] 正在生成 checksums.sha256...")
	if err := WriteChecksums(dest); err != nil {
		return "", err
	}

	base := fmt.Sprintf("dns-stack-%s-%s", c.Role(), c.now().Format("20060102150405"))
	tarZst := filepath.Join(work, base+".tar.zst")
	c.logf("[信息] 正在打包压缩...")
	if err := writeTarZstd(ctx, dest, root, tarZst, 19, 0); err != nil {
		return "", err
	}
	c.logf("[信息] 正在加密(age)...")
	final := filepath.Join(c.ExportDir, base+".tar.zst.age")
	if err := c.encrypt(ctx, tarZst, final); err != nil {
		return "", err
	}
	c.logf("[信息] 正在做解密测试...")
	if err := c.verifyArchive(ctx, final); err != nil {
		os.Remove(final)
		return "", fmt.Errorf("解密测试失败，导出包可能损坏，已删除: %w", err)
	}
	c.logf("[信息] 正在做 SHA256 校验...")
	sum, err := fileSHA256(final)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(final+".sha256",
		[]byte(fmt.Sprintf("%s  %s\n", sum, final)), 0o644); err != nil {
		return "", err
	}
	c.logf("[成功] 导出完成: %s", final)
	return final, nil
}

func (c Config) Import(ctx context.Context, pkg string, allowRollback bool) error {
	c.logf("[信息] [1/12] 检查文件...")
	if info, err := os.Stat(pkg); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("文件不存在或不是普通文件: %s", pkg)
	}
	c.logf("[信息] [2/12] 检查磁盘空间...")
	if err := c.CheckDiskSpace(ctx); err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "dns-stack-import-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	c.logf("[信息] [3/12] 解密...")
	payload := filepath.Join(work, "payload.tar.zst")
	if strings.HasSuffix(pkg, ".age") {
		identity := filepath.Join(c.SecretsDir, identityBasename)
		if _, err := os.Stat(identity); err != nil {
			return fmt.Errorf("找不到 age 私钥，无法解密(该私钥应与生成该导出包的服务器一致，或手动放到 %s)", identity)
		}
		out, err := os.Create(payload)
		if err != nil {
			return err
		}
		cmd := exec.CommandContext(ctx, "age", "-d", "-i", identity, pkg)
		cmd.Stdout = out
		cmd.Stderr = os.Stderr
		runErr := cmd.Run()
		out.Close()
		if runErr != nil {
			return fmt.Errorf("解密失败: %w", runErr)
		}
	} else if err := copyFile(pkg, payload); err != nil {
		return err
	}

	c.logf("[信息] [4/12] 解压到临时目录...")
	extracted := filepath.Join(work, "extracted")
	if err := os.MkdirAll(extracted, 0o755); err != nil {
		return err
	}
	if err := extractTarZstd(ctx, payload, extracted); err != nil {
		return err
	}
	inner, err := singleSubdir(extracted)
	if err != nil {
		return err
	}

	c.logf("[信息] [5/12] 校验 SHA256...")
	if err := VerifyChecksums(inner); err != nil {
		return err
	}
	c.logf("[信息] [6/12] 读取 manifest...")
	mf, err := readManifest(inner)
	if err != nil {
		return err
	}
	c.logf("[信息] [7/12] 检查服务器角色...")
	current := c.Role()
	if current != "unknown" && mf.Role != current {
		return fmt.Errorf("导入包角色(%s)与本机角色(%s)不一致，拒绝导入", mf.Role, current)
	}
	c.logf("[信息] [8/12] 检查 CPU 架构...")
	if arch := machineArch(); mf.Arch != arch {
		c.logf("[警告] 导入包架构(%s)与本机架构(%s)不同，数据库/二进制可能不兼容", mf.Arch, arch)
	}

	c.logf("[信息] [9/12] 创建导入前备份(用于失败回滚)...")
	var preImport string
	if allowRollback && dirHasEntries(c.StateDir) {
		if preImport, err = c.Backup(ctx, false, false); err != nil {
			return fmt.Errorf("导入前备份失败，拒绝继续: %w", err)
		}
		c.logf("[成功] 导入前备份: %s", preImport)
	}

	if err := c.applyImport(ctx, inner); err != nil {
		c.logf("[错误] 导入失败: %v", err)
		if preImport != "" {
			c.logf("[错误] 正在回滚...")
			if rerr := c.Import(ctx, preImport, false); rerr != nil {
				c.logf("[错误] 自动回滚也失败了，请人工检查 %s: %v", preImport, rerr)
			}
		}
		return err
	}
	return c.restartAndProbe(ctx)
}

func (c Config) applyImport(ctx context.Context, inner string) error {
	c.logf("[信息] [10/12] 停止所有会写数据库的服务...")
	for _, unit := range []string{"dns-stack-classify", "dns-stack-verify", "dns-stack-panel", "mosproxy"} {
		exec.CommandContext(ctx, "systemctl", "stop", unit+".service").Run()
	}
	time.Sleep(2 * time.Second)

	c.logf("[信息] [11/12] 导入数据库、配置、规则、人工规则...")
	stateSrc := filepath.Join(inner, "state")
	if entries, err := os.ReadDir(stateSrc); err == nil {
		if err := os.MkdirAll(c.StateDir, 0o755); err != nil {
			return err
		}
		for _, e := range entries {
			if e.Name() == migrationBundle {
				continue
			}
			src := filepath.Join(stateSrc, e.Name())
			dst := filepath.Join(c.StateDir, e.Name())
			if strings.HasSuffix(e.Name(), ".db") {
				os.Remove(dst + "-wal")
				os.Remove(dst + "-shm")
			}
			if e.IsDir() {
				copyTree(src, dst)
			} else {
				copyFile(src, dst)
			}
		}
		bundle := filepath.Join(stateSrc, migrationBundle)
		if _, err := os.Stat(bundle); err == nil {
			if _, err := os.Stat(c.GoBin); err == nil {
				c.logf("[信息]   恢复迁移包(规则 / 人工清单 / chnroute / ECS 累积计时)...")
				cmd := exec.CommandContext(ctx, c.GoBin, "migration-restore",
					"--bundle", bundle, "--state", c.StateDir)
				cmd.Stdout, cmd.Stderr = c.Out, c.Out
				if err := cmd.Run(); err != nil {
					c.logf("[警告]   迁移包恢复未完全成功，请对照上面的跳过项人工确认")
				}
			} else {
				c.logf("[警告]   缺少 %s，备份里的规则与 chnroute 状态未恢复", c.GoBin)
			}
		}
		c.repairDatabases()
	}

	if err := c.mergeConfig(filepath.Join(inner, "config", filepath.Base(c.ConfigFile))); err != nil {
		return err
	}
	stamp := c.now().Format("20060102150405")
	if dirHasEntries(filepath.Join(inner, "secrets")) {
		if dirHasEntries(c.SecretsDir) {
			copyTree(c.SecretsDir, c.SecretsDir+".pre-import-"+stamp)
		}
		copyTree(filepath.Join(inner, "secrets"), c.SecretsDir)
		for _, name := range []string{identityBasename, "github_deploy_key"} {
			os.Chmod(filepath.Join(c.SecretsDir, name), 0o600)
		}
		c.logf("[成功] 已恢复机密文件(面板密码、备份密钥、证书)")
		c.logf("[警告]   证书是**旧服务器 IP** 的，对外服务前请重新签发")
	}
	configRoot := filepath.Dir(c.ConfigFile)
	if dirHasEntries(filepath.Join(inner, "config", "mosproxy")) {
		backupBeside(filepath.Join(configRoot, "mosproxy", "config.yaml"), stamp)
		copyTree(filepath.Join(inner, "config", "mosproxy"), filepath.Join(configRoot, "mosproxy"))
		c.logf("[成功] 已恢复 mosproxy 配置")
	}
	if dirHasEntries(filepath.Join(inner, "config", "unbound.conf.d")) {
		backupBeside("/etc/unbound/unbound.conf.d/dns-stack.conf", stamp)
		copyTree(filepath.Join(inner, "config", "unbound.conf.d"), "/etc/unbound/unbound.conf.d")
		c.logf("[成功] 已恢复 Unbound 配置")
	}
	if dirHasEntries(filepath.Join(inner, "systemd")) {
		copyTree(filepath.Join(inner, "systemd"), c.SystemdDir)
		exec.CommandContext(ctx, "systemctl", "daemon-reload").Run()
		c.logf("[成功] 已恢复 systemd 单元并重新加载")
	}
	c.logf("[警告] ⚠️ 恢复过来的配置里含有**原服务器**的地址与路径，务必核对后再对外提供服务：")
	c.logf("[警告]    - mosproxy: 监听地址/端口、TLS 证书路径、上游(如 WireGuard 对端 10.100.0.x)")
	c.logf("[警告]    - Unbound : interface 监听地址、access-control 网段")
	c.logf("[警告]    - 证书本身需要按新服务器的 IP/域名重新签发")
	os.Chmod(c.SecretsDir, 0o710)
	return nil
}

func (c Config) repairDatabases() {
	entries, err := os.ReadDir(c.StateDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".db") {
			continue
		}
		path := filepath.Join(c.StateDir, e.Name())
		if IntegrityOK(path) {
			continue
		}
		c.logf("[警告]   %s 完整性检查未通过，尝试 REINDEX 修复...", e.Name())
		if db, err := sql.Open("sqlite", path); err == nil {
			db.Exec("REINDEX")
			db.Close()
		}
		if IntegrityOK(path) {
			c.logf("[成功]   %s 已修复", e.Name())
		} else {
			c.logf("[警告]   %s 仍有问题，请人工检查", e.Name())
		}
	}
}

func IntegrityOK(path string) bool {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return false
	}
	defer db.Close()
	var result string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil {
		return false
	}
	return result == "ok"
}

func (c Config) mergeConfig(imported string) error {
	body, err := os.ReadFile(imported)
	if err != nil {
		return nil
	}
	if err := os.WriteFile(c.ConfigFile+".imported", body, 0o640); err != nil {
		return err
	}
	currentBody, _ := os.ReadFile(c.ConfigFile)
	lines := strings.Split(strings.TrimRight(string(currentBody), "\n"), "\n")
	index := make(map[string]int, len(lines))
	for i, line := range lines {
		if key, _, ok := strings.Cut(line, "="); ok {
			if trimmed := strings.TrimSpace(key); trimmed == key && key != "" && !strings.HasPrefix(key, "#") {
				index[key] = i
			}
		}
	}
	merged := 0
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || strings.HasPrefix(key, "#") || strings.TrimSpace(key) != key {
			continue
		}
		if preservedConfigKeys[key] || value == "" {
			continue
		}
		if at, exists := index[key]; exists {
			lines[at] = line
		} else {
			lines = append(lines, line)
			index[key] = len(lines) - 1
		}
		merged++
	}
	if err := os.WriteFile(c.ConfigFile, []byte(strings.Join(lines, "\n")+"\n"), 0o640); err != nil {
		return err
	}
	c.logf("[成功] 已合并 %d 项旧配置(PUBLIC_IPV4/IPV6 保留新机器的值)", merged)
	c.logf("[信息]   旧配置原文另存为 %s.imported，可用于人工核对", c.ConfigFile)
	return nil
}

func (c Config) restartAndProbe(ctx context.Context) error {
	c.logf("[信息] [12/12] 重启服务并执行健康检查...")
	units := []string{"unbound"}
	if c.Role() == "cn-resolver" {
		units = append(units, "mosproxy")
	}
	units = append(units, "dns-stack-helper", "dns-stack-panel")
	for _, unit := range units {
		exec.CommandContext(ctx, "systemctl", "reset-failed", unit+".service").Run()
		if err := exec.CommandContext(ctx, "systemctl", "restart", unit+".service").Run(); err != nil {
			c.logf("[警告] %s 重启失败，请查看 journalctl -u %s", unit, unit)
		}
	}
	time.Sleep(4 * time.Second)
	healthy := true
	for _, unit := range units {
		if err := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit+".service").Run(); err != nil {
			c.logf("[警告] %s 未处于运行状态: journalctl -u %s -n 20", unit, unit)
			healthy = false
		}
	}
	if healthy {
		c.logf("[成功] 健康检查通过：%s 均正常", strings.Join(units, " "))
	} else {
		c.logf("[警告] 健康检查未完全通过，请执行 dns-stack selfcheck 查看详情")
	}
	c.logf("[成功] 导入完成")
	return nil
}

func extractTarZstd(ctx context.Context, archive, dest string) error {
	cmd := exec.CommandContext(ctx, "zstd", "-d", "-q", "-c", archive)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	tr := tar.NewReader(stdout)
	var extractErr error
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			extractErr = err
			break
		}
		target, err := safeJoin(dest, hdr.Name)
		if err != nil {
			extractErr = err
			break
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, 0o755)
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				extractErr = err
				break
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode).Perm())
			if err != nil {
				extractErr = err
				break
			}
			_, copyErr := io.Copy(f, tr)
			f.Close()
			if copyErr != nil {
				extractErr = copyErr
			}
		}
		if extractErr != nil {
			break
		}
	}
	io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	if extractErr != nil {
		return fmt.Errorf("解包失败: %w", extractErr)
	}
	if waitErr != nil {
		return fmt.Errorf("解压失败: %w", waitErr)
	}
	return nil
}

func safeJoin(root, name string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(name))
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return "", fmt.Errorf("包内路径越界: %s", name)
	}
	target := filepath.Join(root, clean)
	if rel, err := filepath.Rel(root, target); err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("包内路径越界: %s", name)
	}
	return target, nil
}

func readManifest(inner string) (Manifest, error) {
	body, err := os.ReadFile(filepath.Join(inner, manifestFile))
	if err != nil {
		return Manifest{}, fmt.Errorf("缺少 %s", manifestFile)
	}
	var mf Manifest
	if err := json.Unmarshal(body, &mf); err != nil {
		return Manifest{}, fmt.Errorf("manifest 解析失败: %w", err)
	}
	return mf, nil
}

func singleSubdir(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() {
			return filepath.Join(dir, e.Name()), nil
		}
	}
	return "", fmt.Errorf("包内没有数据目录")
}

func dirHasEntries(dir string) bool {
	entries, err := os.ReadDir(dir)
	return err == nil && len(entries) > 0
}

func backupBeside(path, stamp string) {
	if _, err := os.Stat(path); err == nil {
		copyFile(path, path+".pre-import-"+stamp)
	}
}
