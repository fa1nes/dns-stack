package panel

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readBundle(t *testing.T, raw []byte) (map[string][]byte, migrationManifest) {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("不是合法 gzip: %v", err)
	}
	files := map[string][]byte{}
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar 解包失败: %v", err)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", header.Name, err)
		}
		files[header.Name] = data
	}
	var manifest migrationManifest
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatalf("manifest 不是合法 JSON: %v", err)
	}
	return files, manifest
}

func TestMigrationBundleCarriesRulesAndManualLists(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "chnroute"), 0o700); err != nil {
		t.Fatal(err)
	}
	written := map[string]string{
		"manual-cn-zones.txt":       "akamaiedge.net\n",
		"cn.txt":                    "# generated-at: 1\nqq.com\nbaidu.com\n",
		"chnroute/direct4.txt":      "116.0.0.0/8\n",
		"chnroute/cn-authority.txt": "116.1.1.1/32\n",
	}
	for name, content := range written {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var buffer bytes.Buffer
	now := time.Unix(1700000000, 0)

	cfg := Config{StateDir: root, ECSConfPath: filepath.Join(root, "absent-ecs.conf")}
	manifest, err := WriteMigrationBundle(&buffer, cfg, now)
	if err != nil {
		t.Fatalf("打包失败: %v", err)
	}
	files, embedded := readBundle(t, buffer.Bytes())

	for name, content := range map[string]string{
		"manual/manual-cn-zones.txt":      written["manual-cn-zones.txt"],
		"rules/cn.txt":                    written["cn.txt"],
		"state/chnroute/direct4.txt":      written["chnroute/direct4.txt"],
		"state/chnroute/cn-authority.txt": written["chnroute/cn-authority.txt"],
	} {
		if got := string(files[name]); got != content {
			t.Fatalf("%s 内容不符: %q", name, got)
		}
	}
	if embedded.GeneratedAt != now.Unix() || embedded.Kind != "dns-stack-migration" {
		t.Fatalf("manifest 头不符: %+v", embedded)
	}

	byPath := map[string]migrationFile{}
	for _, item := range embedded.Files {
		byPath[item.Path] = item
	}
	entry, ok := byPath["rules/cn.txt"]
	if !ok {
		t.Fatal("manifest 未记录 rules/cn.txt")
	}
	sum := sha256.Sum256(files["rules/cn.txt"])
	if entry.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("cn.txt 哈希不符: %s", entry.SHA256)
	}

	if entry.Lines != 2 {
		t.Fatalf("cn.txt 正文行数应为 2，实际 %d", entry.Lines)
	}
	if manifest.TotalBytes != embedded.TotalBytes {
		t.Fatalf("返回值与包内 manifest 不一致")
	}
}

func TestMigrationBundleNeverCarriesSecrets(t *testing.T) {
	root := t.TempDir()
	secrets := filepath.Join(root, "secrets")
	if err := os.MkdirAll(secrets, 0o700); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"auth.json", "cert.pem", "key.pem"} {
		if err := os.WriteFile(filepath.Join(secrets, name), []byte("SECRET"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	config := filepath.Join(root, "config.env")
	if err := os.WriteFile(config, []byte("GITHUB_TOKEN=SECRET\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	cfg := Config{StateDir: root, ConfigPath: config,
		AuthPath:    filepath.Join(secrets, "auth.json"),
		ECSConfPath: filepath.Join(root, "absent-ecs.conf")}
	if _, err := WriteMigrationBundle(&buffer, cfg, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buffer.Bytes(), []byte("SECRET")) {
		t.Fatal("压缩流里出现了明文密钥")
	}
	files, manifest := readBundle(t, buffer.Bytes())
	for name, data := range files {
		if bytes.Contains(data, []byte("SECRET")) {
			t.Fatalf("%s 含密钥内容", name)
		}
	}

	if len(manifest.Excluded) == 0 {
		t.Fatal("manifest 未列出任何排除项")
	}
	for _, item := range manifest.Excluded {
		if strings.TrimSpace(item.Reason) == "" {
			t.Fatalf("排除项 %s 没有写理由", item.Path)
		}
	}
	found := false
	for _, item := range manifest.Excluded {
		if item.Path == config {
			found = true
		}
	}
	if !found {
		t.Fatal("config.env 未出现在排除清单里")
	}
}

func TestMigrationBundleRecordsMissingFiles(t *testing.T) {
	root := t.TempDir()
	var buffer bytes.Buffer
	manifest, err := WriteMigrationBundle(&buffer, Config{StateDir: root,
		ECSConfPath: filepath.Join(root, "absent-ecs.conf")}, time.Unix(1, 0))
	if err != nil {
		t.Fatalf("空状态目录不该让整包失败: %v", err)
	}
	if len(manifest.Files) != 0 {
		t.Fatalf("不该有文件进包: %+v", manifest.Files)
	}

	if len(manifest.Missing) == 0 {
		t.Fatal("缺失文件没有被记录")
	}
	for _, item := range manifest.Missing {
		if item.Reason != "文件不存在" {
			t.Fatalf("%s 的原因应为文件不存在，实际 %q", item.Path, item.Reason)
		}
	}
	files, _ := readBundle(t, buffer.Bytes())
	if len(files) != 1 {
		t.Fatalf("空包里应只有 manifest.json，实际 %d 个文件", len(files))
	}
}

func TestMigrationExportRejectsNonGET(t *testing.T) {
	server := New(Config{StateDir: t.TempDir()})
	response := httptest.NewRecorder()
	server.migrationExport(response, httptest.NewRequest("POST", "/api/migration-export", nil))
	if response.Code != 405 {
		t.Fatalf("非 GET 应返回 405，实际 %d", response.Code)
	}
}
