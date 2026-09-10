package panel

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	MigrationMaxBundleBytes = 64 << 20
	MigrationMaxFileBytes   = 32 << 20
)

type RestoreOutcome struct {
	Path    string `json:"path"`
	Target  string `json:"target,omitempty"`
	Bytes   int64  `json:"bytes,omitempty"`
	Action  string `json:"action"`
	Reason  string `json:"reason,omitempty"`
	Changed bool   `json:"changed"`
}

type RestoreReport struct {
	Kind        string           `json:"kind"`
	Version     int              `json:"version"`
	GeneratedAt int64            `json:"generated_at"`
	BackupDir   string           `json:"backup_dir,omitempty"`
	Applied     []RestoreOutcome `json:"applied"`
	Skipped     []RestoreOutcome `json:"skipped"`
	DryRun      bool             `json:"dry_run"`
}

type RestoreOptions struct {
	DryRun    bool
	BackupDir string
	Now       time.Time
}

func migrationTargets(cfg Config) map[string]migrationEntry {
	out := map[string]migrationEntry{}
	for _, entry := range migrationEntries(cfg) {
		out[entry.archive] = entry
	}
	return out
}

func readMigrationArchive(r io.Reader) (map[string][]byte, error) {
	gz, err := gzip.NewReader(io.LimitReader(r, MigrationMaxBundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("不是有效的 gzip 包: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	var total int64
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar 解析失败: %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		name := filepath.ToSlash(strings.TrimPrefix(header.Name, "./"))
		if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
			return nil, fmt.Errorf("包内含非法路径: %s", header.Name)
		}
		if header.Size > MigrationMaxFileBytes {
			return nil, fmt.Errorf("%s 超过单文件上限", name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, MigrationMaxFileBytes+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > MigrationMaxFileBytes {
			return nil, fmt.Errorf("%s 超过单文件上限", name)
		}
		total += int64(len(data))
		if total > MigrationMaxBundleBytes {
			return nil, fmt.Errorf("解包后总体积超过上限")
		}
		files[name] = data
	}
	return files, nil
}

func RestoreMigrationBundle(r io.Reader, cfg Config, opt RestoreOptions) (RestoreReport, error) {
	report := RestoreReport{Applied: []RestoreOutcome{}, Skipped: []RestoreOutcome{}, DryRun: opt.DryRun}

	files, err := readMigrationArchive(r)
	if err != nil {
		return report, err
	}
	raw, ok := files["manifest.json"]
	if !ok {
		return report, fmt.Errorf("包内没有 manifest.json，拒绝导入")
	}
	var manifest migrationManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return report, fmt.Errorf("manifest.json 解析失败: %w", err)
	}
	if manifest.Kind != "dns-stack-migration" {
		return report, fmt.Errorf("manifest kind 是 %q，不是 dns-stack 迁移包", manifest.Kind)
	}
	if manifest.Version > migrationManifestVersion {
		return report, fmt.Errorf("包版本 %d 高于本机支持的 %d，先升级再导入",
			manifest.Version, migrationManifestVersion)
	}
	report.Kind = manifest.Kind
	report.Version = manifest.Version
	report.GeneratedAt = manifest.GeneratedAt

	expected := map[string]migrationFile{}
	for _, item := range manifest.Files {
		expected[item.Path] = item
	}
	targets := migrationTargets(cfg)

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "manifest.json" {
			continue
		}
		if _, ok := expected[name]; !ok {
			report.Skipped = append(report.Skipped, RestoreOutcome{
				Path: name, Action: "skip", Reason: "不在 manifest.json 的文件清单里"})
			continue
		}
		if _, ok := targets[name]; !ok {
			report.Skipped = append(report.Skipped, RestoreOutcome{
				Path: name, Action: "skip", Reason: "不在本机允许写入的迁移清单里"})
		}
	}

	for _, item := range manifest.Files {
		entry, allowed := targets[item.Path]
		if !allowed {
			continue
		}
		data, present := files[item.Path]
		if !present {
			report.Skipped = append(report.Skipped, RestoreOutcome{
				Path: item.Path, Action: "skip", Reason: "manifest 里有但包内缺失"})
			continue
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != item.SHA256 {
			report.Skipped = append(report.Skipped, RestoreOutcome{
				Path: item.Path, Action: "skip", Reason: "sha256 与 manifest 不符，包可能损坏"})
			continue
		}
		if same, err := sameContent(entry.source, data); err == nil && same {
			report.Applied = append(report.Applied, RestoreOutcome{
				Path: item.Path, Target: filepath.ToSlash(entry.source),
				Bytes: int64(len(data)), Action: "unchanged"})
			continue
		}
		if opt.DryRun {
			report.Applied = append(report.Applied, RestoreOutcome{
				Path: item.Path, Target: filepath.ToSlash(entry.source),
				Bytes: int64(len(data)), Action: "would-write", Changed: true})
			continue
		}
		if opt.BackupDir != "" {
			if err := backupExisting(entry.source, opt.BackupDir, item.Path); err != nil {
				return report, fmt.Errorf("备份 %s 失败: %w", entry.source, err)
			}
		}
		if err := writeRestored(entry.source, data); err != nil {
			return report, fmt.Errorf("写入 %s 失败: %w", entry.source, err)
		}
		report.Applied = append(report.Applied, RestoreOutcome{
			Path: item.Path, Target: filepath.ToSlash(entry.source),
			Bytes: int64(len(data)), Action: "written", Changed: true})
	}
	if opt.BackupDir != "" && !opt.DryRun {
		report.BackupDir = filepath.ToSlash(opt.BackupDir)
	}
	sort.Slice(report.Skipped, func(i, j int) bool { return report.Skipped[i].Path < report.Skipped[j].Path })
	return report, nil
}

func sameContent(path string, data []byte) (bool, error) {
	existing, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	if len(existing) != len(data) {
		return false, nil
	}
	a := sha256.Sum256(existing)
	b := sha256.Sum256(data)
	return a == b, nil
}

func backupExisting(source, backupDir, archive string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	dest := filepath.Join(backupDir, filepath.FromSlash(archive))
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o644)
}

func writeRestored(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temp := path + ".restore.tmp"
	if err := os.WriteFile(temp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		os.Remove(temp)
		return err
	}
	return nil
}
