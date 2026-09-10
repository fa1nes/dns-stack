package panel

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func buildBundle(t *testing.T, files map[string][]byte, manifest any) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	write := func(name string, data []byte) {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(data)),
			ModTime: time.Unix(0, 0), Format: tar.FormatPAX,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range files {
		write(name, data)
	}
	if manifest != nil {
		encoded, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		write("manifest.json", encoded)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func restoreCfg(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	return Config{StateDir: dir, ECSConfPath: filepath.Join(dir, "ecs.conf")}
}

func TestRestoreWritesWhitelistedFiles(t *testing.T) {
	cfg := restoreCfg(t)
	payload := []byte("example.com\n")
	bundle := buildBundle(t,
		map[string][]byte{"manual/manual-cn-zones.txt": payload},
		migrationManifest{
			Kind: "dns-stack-migration", Version: 1, GeneratedAt: 100,
			Files: []migrationFile{{Path: "manual/manual-cn-zones.txt",
				Bytes: int64(len(payload)), SHA256: sum(payload)}},
		})
	report, err := RestoreMigrationBundle(bytes.NewReader(bundle), cfg, RestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Applied) != 1 || report.Applied[0].Action != "written" {
		t.Fatalf("applied=%#v", report.Applied)
	}
	got, err := os.ReadFile(filepath.Join(cfg.StateDir, "manual-cn-zones.txt"))
	if err != nil || string(got) != string(payload) {
		t.Fatalf("落盘内容不对: %q %v", got, err)
	}
}

func TestRestoreRejectsPathOutsideWhitelist(t *testing.T) {
	cfg := restoreCfg(t)
	evil := []byte("pwned")
	bundle := buildBundle(t,
		map[string][]byte{"secrets/auth.json": evil},
		migrationManifest{
			Kind: "dns-stack-migration", Version: 1,
			Files: []migrationFile{{Path: "secrets/auth.json",
				Bytes: int64(len(evil)), SHA256: sum(evil)}},
		})
	report, err := RestoreMigrationBundle(bytes.NewReader(bundle), cfg, RestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Applied) != 0 {
		t.Fatalf("清单外的路径被写入了: %#v", report.Applied)
	}
	if len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Reason, "允许写入") {
		t.Fatalf("skipped=%#v", report.Skipped)
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDir, "secrets", "auth.json")); err == nil {
		t.Fatal("清单外的文件竟然落盘了")
	}
}

func TestRestoreRejectsTraversalPath(t *testing.T) {
	cfg := restoreCfg(t)
	bundle := buildBundle(t,
		map[string][]byte{"../../etc/passwd": []byte("x")}, nil)
	if _, err := RestoreMigrationBundle(bytes.NewReader(bundle), cfg, RestoreOptions{}); err == nil {
		t.Fatal("含 .. 的路径必须整包拒绝")
	}
}

func TestRestoreRejectsChecksumMismatch(t *testing.T) {
	cfg := restoreCfg(t)
	payload := []byte("real\n")
	bundle := buildBundle(t,
		map[string][]byte{"manual/manual-gfw.txt": payload},
		migrationManifest{
			Kind: "dns-stack-migration", Version: 1,
			Files: []migrationFile{{Path: "manual/manual-gfw.txt",
				Bytes: int64(len(payload)), SHA256: sum([]byte("tampered"))}},
		})
	report, err := RestoreMigrationBundle(bytes.NewReader(bundle), cfg, RestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Applied) != 0 {
		t.Fatalf("sha256 不符仍被写入: %#v", report.Applied)
	}
	if len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Reason, "sha256") {
		t.Fatalf("skipped=%#v", report.Skipped)
	}
}

func TestRestoreRejectsForeignManifest(t *testing.T) {
	cfg := restoreCfg(t)
	bundle := buildBundle(t, map[string][]byte{},
		map[string]any{"kind": "something-else", "version": 1})
	if _, err := RestoreMigrationBundle(bytes.NewReader(bundle), cfg, RestoreOptions{}); err == nil {
		t.Fatal("非 dns-stack 迁移包必须拒绝")
	}
}

func TestRestoreRejectsMissingManifest(t *testing.T) {
	cfg := restoreCfg(t)
	bundle := buildBundle(t, map[string][]byte{"rules/cn.txt": []byte("a.com\n")}, nil)
	if _, err := RestoreMigrationBundle(bytes.NewReader(bundle), cfg, RestoreOptions{}); err == nil {
		t.Fatal("没有 manifest.json 必须拒绝")
	}
}

func TestRestoreRejectsNewerVersion(t *testing.T) {
	cfg := restoreCfg(t)
	bundle := buildBundle(t, map[string][]byte{},
		migrationManifest{Kind: "dns-stack-migration", Version: migrationManifestVersion + 1})
	if _, err := RestoreMigrationBundle(bytes.NewReader(bundle), cfg, RestoreOptions{}); err == nil {
		t.Fatal("更高版本的包必须拒绝而不是当成兼容")
	}
}

func TestRestoreDryRunWritesNothing(t *testing.T) {
	cfg := restoreCfg(t)
	payload := []byte("a.com\n")
	bundle := buildBundle(t,
		map[string][]byte{"rules/cn.txt": payload},
		migrationManifest{
			Kind: "dns-stack-migration", Version: 1,
			Files: []migrationFile{{Path: "rules/cn.txt",
				Bytes: int64(len(payload)), SHA256: sum(payload)}},
		})
	report, err := RestoreMigrationBundle(bytes.NewReader(bundle), cfg, RestoreOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Applied) != 1 || report.Applied[0].Action != "would-write" {
		t.Fatalf("applied=%#v", report.Applied)
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDir, "cn.txt")); err == nil {
		t.Fatal("dry-run 竟然落盘了")
	}
}

func TestRestoreBacksUpAndDetectsUnchanged(t *testing.T) {
	cfg := restoreCfg(t)
	target := filepath.Join(cfg.StateDir, "cn.txt")
	if err := os.WriteFile(target, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	payload := []byte("new\n")
	manifest := migrationManifest{
		Kind: "dns-stack-migration", Version: 1,
		Files: []migrationFile{{Path: "rules/cn.txt",
			Bytes: int64(len(payload)), SHA256: sum(payload)}},
	}
	bundle := buildBundle(t, map[string][]byte{"rules/cn.txt": payload}, manifest)
	backup := filepath.Join(cfg.StateDir, "bk")
	if _, err := RestoreMigrationBundle(bytes.NewReader(bundle), cfg,
		RestoreOptions{BackupDir: backup}); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(filepath.Join(backup, "rules", "cn.txt"))
	if err != nil || string(saved) != "old\n" {
		t.Fatalf("原文件没被备份: %q %v", saved, err)
	}

	bundle2 := buildBundle(t, map[string][]byte{"rules/cn.txt": payload}, manifest)
	report, err := RestoreMigrationBundle(bytes.NewReader(bundle2), cfg,
		RestoreOptions{BackupDir: backup})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Applied) != 1 || report.Applied[0].Action != "unchanged" {
		t.Fatalf("重复导入应识别为 unchanged: %#v", report.Applied)
	}
}

func TestRestoreReportsExtraFilesInBundle(t *testing.T) {
	cfg := restoreCfg(t)
	payload := []byte("a.com\n")
	bundle := buildBundle(t,
		map[string][]byte{"rules/cn.txt": payload, "stowaway.txt": []byte("x")},
		migrationManifest{
			Kind: "dns-stack-migration", Version: 1,
			Files: []migrationFile{{Path: "rules/cn.txt",
				Bytes: int64(len(payload)), SHA256: sum(payload)}},
		})
	report, err := RestoreMigrationBundle(bytes.NewReader(bundle), cfg, RestoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range report.Skipped {
		if item.Path == "stowaway.txt" && strings.Contains(item.Reason, "manifest") {
			found = true
		}
	}
	if !found {
		t.Fatalf("清单外夹带的文件必须被报出来: %#v", report.Skipped)
	}
	if _, err := os.Stat(filepath.Join(cfg.StateDir, "stowaway.txt")); err == nil {
		t.Fatal("夹带文件竟然落盘了")
	}
}
