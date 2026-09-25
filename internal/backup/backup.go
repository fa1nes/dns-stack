package backup

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/config"
	"github.com/dns-stack/dns-stack/internal/stack"

	_ "modernc.org/sqlite"
)

const (
	ModeConfig = "config"
	ModeState  = "state"
	ModeFull   = "full"

	minFreeKB        = 512000
	checksumFile     = "checksums.sha256"
	manifestFile     = "manifest.json"
	migrationBundle  = "migration.tar.gz"
	identityBasename = "backup-age-identity.txt"
	recipientBase    = "backup-age-recipient.txt"
)

type Config struct {
	ConfigFile string
	SecretsDir string
	StateDir   string
	LogDir     string
	BackupDir  string
	ExportDir  string
	SystemdDir string
	GoBin      string
	Out        io.Writer
	Now        func() time.Time
}

func DefaultConfig() Config {
	return Config{
		ConfigFile: "/etc/dns-stack/config.env",
		SecretsDir: "/etc/dns-stack/secrets",
		StateDir:   "/var/lib/dns-stack",
		LogDir:     "/var/log/dns-stack",
		BackupDir:  "/var/backups/dns-stack",
		ExportDir:  "/srv/dns-stack/export",
		SystemdDir: "/etc/systemd/system",
		GoBin:      "/opt/dns-stack/bin/dns-stack-go",
		Out:        os.Stdout,
		Now:        time.Now,
	}
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c Config) logf(format string, args ...any) {
	if c.Out == nil {
		return
	}
	fmt.Fprintf(c.Out, format+"\n", args...)
}

func (c Config) Role() string {
	role := config.ReadKeys(c.ConfigFile, "ROLE")["ROLE"]
	if role == "" {
		return "unknown"
	}
	return role
}

func (c Config) configInt(key string, fallback, low, high int) int {
	v, err := strconv.Atoi(config.ReadKeys(c.ConfigFile, key)[key])
	if err != nil || v < low || v > high {
		return fallback
	}
	return v
}

func (c Config) CheckDiskSpace(ctx context.Context) error {
	if err := os.MkdirAll(c.BackupDir, 0o755); err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, "df", "-Pk", c.BackupDir).Output()
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 4 {
		return nil
	}
	avail, err := strconv.Atoi(fields[3])
	if err != nil {
		return nil
	}
	if avail < minFreeKB {
		return fmt.Errorf("磁盘空间不足(可用 %dMB)，取消操作", avail/1024)
	}
	return nil
}

func SnapshotSQLite(src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		return nil
	}
	db, err := sql.Open("sqlite", src+"?_pragma=busy_timeout(15000)")
	if err != nil {
		return err
	}
	defer db.Close()
	os.Remove(dst)
	_, err = db.Exec("VACUUM INTO ?", dst)
	return err
}

func (c Config) CollectPayload(ctx context.Context, dest, mode string, includeSecrets, includeLogs bool) error {
	for _, sub := range []string{"config", "state", "versions", "systemd"} {
		if err := os.MkdirAll(filepath.Join(dest, sub), 0o755); err != nil {
			return err
		}
	}
	copyFile(c.ConfigFile, filepath.Join(dest, "config", filepath.Base(c.ConfigFile)))
	copyTree("/etc/unbound/unbound.conf.d", filepath.Join(dest, "config", "unbound.conf.d"))
	for _, dir := range []string{filepath.Join(filepath.Dir(c.ConfigFile), "mosproxy"), "/etc/mosproxy"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		os.MkdirAll(filepath.Join(dest, "config", "mosproxy"), 0o755)
		for _, e := range entries {
			if e.IsDir() || strings.Contains(e.Name(), ".bak") {
				continue
			}
			copyFile(filepath.Join(dir, e.Name()), filepath.Join(dest, "config", "mosproxy", e.Name()))
		}
		break
	}
	copyFile("/opt/dns-stack/versions.lock", filepath.Join(dest, "versions", "versions.lock"))
	c.collectSystemd(filepath.Join(dest, "systemd"))

	if mode == ModeState || mode == ModeFull {
		if err := c.collectState(ctx, dest); err != nil {
			return err
		}
	}
	if includeLogs {
		os.MkdirAll(filepath.Join(dest, "logs"), 0o755)
		if entries, err := os.ReadDir(c.LogDir); err == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".log") {
					copyFile(filepath.Join(c.LogDir, e.Name()), filepath.Join(dest, "logs", e.Name()))
				}
			}
		}
	}
	if includeSecrets {
		copyTree(c.SecretsDir, filepath.Join(dest, "secrets"))
	}
	return nil
}

func (c Config) collectState(ctx context.Context, dest string) error {
	stateOut := filepath.Join(dest, "state")
	if c.Role() != stack.RoleCNResolver {
		return nil
	}
	os.MkdirAll(filepath.Join(stateOut, "rule-history"), 0o755)
	os.MkdirAll(filepath.Join(stateOut, "sync-state"), 0o755)
	if err := SnapshotSQLite(filepath.Join(c.StateDir, "collector.db"),
		filepath.Join(stateOut, "collector.db")); err != nil {
		c.logf("  ! collector.db 快照失败: %v", err)
	}
	copyTree(filepath.Join(c.StateDir, "rule-history"), filepath.Join(stateOut, "rule-history"))
	copyTree(filepath.Join(c.StateDir, "sync-state"), filepath.Join(stateOut, "sync-state"))
	if _, err := os.Stat(c.GoBin); err != nil {
		c.logf("  ! 缺少 %s，本次备份缺少规则与 chnroute 状态", c.GoBin)
		return nil
	}
	cmd := exec.CommandContext(ctx, c.GoBin, "migration-export",
		"--out", filepath.Join(stateOut, migrationBundle), "--state", c.StateDir)
	if err := cmd.Run(); err != nil {
		c.logf("  ! 迁移包导出失败，本次备份缺少规则与 chnroute 状态: %v", err)
	}
	return nil
}

func (c Config) collectSystemd(dest string) {
	for _, module := range stack.All() {
		if !module.HasRole(c.Role()) || module.CronDriven() {
			continue
		}
		for _, suffix := range []string{".service", ".timer"} {
			src := filepath.Join(c.SystemdDir, module.Unit+suffix)
			if _, err := os.Stat(src); err != nil {
				continue
			}
			_ = copyFile(src, filepath.Join(dest, module.Unit+suffix))
		}
	}
}

type Manifest struct {
	Role           string `json:"role"`
	Arch           string `json:"arch"`
	Hostname       string `json:"hostname"`
	CreatedAt      string `json:"created_at"`
	Mode           string `json:"mode"`
	IncludeSecrets bool   `json:"include_secrets"`
	IncludeLogs    bool   `json:"include_logs"`
	SchemaVersion  int    `json:"schema_version"`
}

func (c Config) WriteManifest(dest, mode string, includeSecrets, includeLogs bool) error {
	host, _ := os.Hostname()
	body, err := json.MarshalIndent(Manifest{
		Role:           c.Role(),
		Arch:           machineArch(),
		Hostname:       host,
		CreatedAt:      c.now().UTC().Format("2006-01-02T15:04:05Z"),
		Mode:           mode,
		IncludeSecrets: includeSecrets,
		IncludeLogs:    includeLogs,
		SchemaVersion:  1,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dest, manifestFile), append(body, '\n'), 0o644)
}

func machineArch() string {
	if out, err := exec.Command("uname", "-m").Output(); err == nil {
		if v := strings.TrimSpace(string(out)); v != "" {
			return v
		}
	}
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return runtime.GOARCH
	}
}

func WriteChecksums(dest string) error {
	var lines []string
	err := filepath.WalkDir(dest, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() == checksumFile {
			return nil
		}
		sum, err := fileSHA256(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dest, path)
		if err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("%s  ./%s", sum, filepath.ToSlash(rel)))
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(lines)
	body := ""
	if len(lines) > 0 {
		body = strings.Join(lines, "\n") + "\n"
	}
	return os.WriteFile(filepath.Join(dest, checksumFile), []byte(body), 0o644)
}

func VerifyChecksums(dest string) error {
	body, err := os.ReadFile(filepath.Join(dest, checksumFile))
	if err != nil {
		return fmt.Errorf("缺少 %s: %w", checksumFile, err)
	}
	var bad []string
	checked := 0
	for _, line := range strings.Split(string(body), "\n") {
		sum, rel, ok := strings.Cut(strings.TrimSpace(line), "  ")
		if !ok || sum == "" {
			continue
		}
		checked++
		actual, err := fileSHA256(filepath.Join(dest, filepath.FromSlash(strings.TrimPrefix(rel, "./"))))
		if err != nil || actual != sum {
			bad = append(bad, rel)
		}
	}
	if checked == 0 {
		return fmt.Errorf("%s 里一条记录都没有，校验等于没做", checksumFile)
	}
	if len(bad) > 0 {
		return fmt.Errorf("%d 个文件校验和不匹配: %s", len(bad), strings.Join(head(bad, 5), ", "))
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

func writeTarZstd(ctx context.Context, srcDir, rootName, out string, level, threads int) error {
	file, err := os.Create(out)
	if err != nil {
		return err
	}
	defer file.Close()
	cmd := exec.CommandContext(ctx, "zstd", "-q",
		fmt.Sprintf("-%d", level), fmt.Sprintf("-T%d", threads))
	cmd.Stdout = file
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	tw := tar.NewWriter(stdin)
	walkErr := filepath.WalkDir(srcDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		name := rootName
		if rel != "." {
			name = rootName + "/" + filepath.ToSlash(rel)
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = name
		if d.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(tw, src)
		return err
	})
	tarErr := tw.Close()
	stdin.Close()
	waitErr := cmd.Wait()
	for _, err := range []error{walkErr, tarErr, waitErr} {
		if err != nil {
			os.Remove(out)
			return err
		}
	}
	return nil
}

func (c Config) ensureAgeKeys() (string, error) {
	identity := filepath.Join(c.SecretsDir, identityBasename)
	recipient := filepath.Join(c.SecretsDir, recipientBase)
	if body, err := os.ReadFile(recipient); err == nil && strings.TrimSpace(string(body)) != "" {
		if _, err := os.Stat(identity); err == nil {
			return strings.TrimSpace(string(body)), nil
		}
	}
	if _, err := os.Stat(identity); err != nil {
		if err := os.MkdirAll(c.SecretsDir, 0o710); err != nil {
			return "", err
		}
		if err := exec.Command("age-keygen", "-o", identity).Run(); err != nil {
			return "", fmt.Errorf("生成 age 密钥失败: %w", err)
		}
		os.Chmod(identity, 0o600)
	}
	body, err := os.ReadFile(identity)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		if key, ok := strings.CutPrefix(strings.TrimSpace(line), "# public key: "); ok {
			if err := os.WriteFile(recipient, []byte(key+"\n"), 0o644); err != nil {
				return "", err
			}
			return key, nil
		}
	}
	return "", fmt.Errorf("%s 里没有 public key 行", identity)
}

func (c Config) encrypt(ctx context.Context, src, dst string) error {
	recipient, err := c.ensureAgeKeys()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "age", "-r", recipient, "-o", dst, src)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (c Config) verifyArchive(ctx context.Context, path string) error {
	if strings.HasSuffix(path, ".age") {
		identity := filepath.Join(c.SecretsDir, identityBasename)
		dec := exec.CommandContext(ctx, "age", "-d", "-i", identity, path)
		test := exec.CommandContext(ctx, "zstd", "-t", "-q")
		pipe, err := dec.StdoutPipe()
		if err != nil {
			return err
		}
		test.Stdin = pipe
		if err := test.Start(); err != nil {
			return err
		}
		if err := dec.Run(); err != nil {
			test.Process.Kill()
			test.Wait()
			return fmt.Errorf("解密测试失败: %w", err)
		}
		pipe.Close()
		return test.Wait()
	}
	return exec.CommandContext(ctx, "zstd", "-t", "-q", path).Run()
}

func (c Config) Backup(ctx context.Context, includeSecrets, automatic bool) (string, error) {
	if err := c.CheckDiskSpace(ctx); err != nil {
		return "", err
	}
	level := c.configInt("BACKUP_ZSTD_LEVEL", 6, 1, 19)
	threads := c.configInt("BACKUP_ZSTD_THREADS", 2, 1, 8)
	dailyKeep := c.configInt("BACKUP_RETENTION_DAILY", 3, 1, 365)
	weeklyKeep := c.configInt("BACKUP_RETENTION_WEEKLY", 2, 1, 104)

	now := c.now()
	stamp := now.Format("20060102150405")
	prefix := "daily"
	if automatic && now.Weekday() == time.Sunday {
		prefix = "weekly"
	}
	work, err := os.MkdirTemp("", "dns-stack-backup-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(work)
	root := "dns-stack-backup-" + stamp
	dest := filepath.Join(work, root)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return "", err
	}

	c.logf("[信息] 正在收集配置和运行数据...")
	if err := c.CollectPayload(ctx, dest, ModeFull, includeSecrets, false); err != nil {
		return "", err
	}
	c.logf("[信息] 正在生成 manifest 和校验和...")
	if err := c.WriteManifest(dest, ModeFull, includeSecrets, false); err != nil {
		return "", err
	}
	if err := WriteChecksums(dest); err != nil {
		return "", err
	}

	c.logf("[信息] 正在打包压缩...")
	tarZst := filepath.Join(c.BackupDir, prefix+"-"+stamp+".tar.zst")
	if err := writeTarZstd(ctx, dest, root, tarZst, level, threads); err != nil {
		return "", err
	}
	outFile := tarZst
	if includeSecrets {
		outFile = tarZst + ".age"
		if err := c.encrypt(ctx, tarZst, outFile); err != nil {
			os.Remove(tarZst)
			return "", err
		}
		os.Remove(tarZst)
	}

	c.logf("[信息] 正在验证压缩包...")
	if err := c.verifyArchive(ctx, outFile); err != nil {
		os.Remove(outFile)
		return "", fmt.Errorf("压缩包自检失败，已删除该文件: %w", err)
	}
	c.warnOnSuddenShrink(prefix, outFile)
	c.cleanupOld(dailyKeep, weeklyKeep)
	c.logf("[成功] 备份完成: %s", outFile)
	return outFile, nil
}

func (c Config) warnOnSuddenShrink(prefix, outFile string) {
	files := c.archivesWithPrefix(prefix)
	if len(files) < 2 {
		return
	}
	newInfo, err1 := os.Stat(outFile)
	prevInfo, err2 := os.Stat(files[1])
	if err1 != nil || err2 != nil || prevInfo.Size() == 0 {
		return
	}
	if newInfo.Size() < prevInfo.Size()/2 {
		c.logf("[警告] 本次备份体积仅为上一份的 %d%%", newInfo.Size()*100/prevInfo.Size())
		c.logf("[警告]   本次 %d 字节 / 上次 %d 字节", newInfo.Size(), prevInfo.Size())
		c.logf("[警告]   若非刚清理过数据，请检查数据库完整性: dns-stack selfcheck")
	}
}

func (c Config) archivesWithPrefix(prefix string) []string {
	entries, err := os.ReadDir(c.BackupDir)
	if err != nil {
		return nil
	}
	type item struct {
		path string
		mod  time.Time
	}
	var list []item
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, prefix+"-") || !strings.Contains(name, ".tar.zst") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		list = append(list, item{filepath.Join(c.BackupDir, name), info.ModTime()})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].mod.After(list[j].mod) })
	out := make([]string, 0, len(list))
	for _, it := range list {
		out = append(out, it.path)
	}
	return out
}

func (c Config) cleanupOld(dailyKeep, weeklyKeep int) {
	c.Prune(dailyKeep, weeklyKeep)
}

type PruneResult struct {
	Removed []string
	Bytes   int64
}

func (c Config) Prune(dailyKeep, weeklyKeep int) PruneResult {
	var out PruneResult
	for prefix, keep := range map[string]int{"daily": dailyKeep, "weekly": weeklyKeep} {
		files := c.archivesWithPrefix(prefix)
		for i := keep; i < len(files); i++ {
			if info, err := os.Stat(files[i]); err == nil {
				out.Bytes += info.Size()
			}
			if os.Remove(files[i]) == nil {
				out.Removed = append(out.Removed, filepath.Base(files[i]))
			}
		}
	}
	sort.Strings(out.Removed)
	return out
}

func (c Config) PruneWithConfig() PruneResult {
	return c.Prune(
		c.configInt("BACKUP_RETENTION_DAILY", 3, 1, 365),
		c.configInt("BACKUP_RETENTION_WEEKLY", 2, 1, 104))
}

func copyFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil || !info.Mode().IsRegular() {
		return err
	}
	body, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(dst, body, info.Mode().Perm()); err != nil {
		return err
	}
	return os.Chtimes(dst, info.ModTime(), info.ModTime())
}

func copyTree(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil || !info.IsDir() {
		return err
	}
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return nil
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		copyFile(path, target)
		return nil
	})
}

func head(values []string, n int) []string {
	if len(values) > n {
		return values[:n]
	}
	return values
}
