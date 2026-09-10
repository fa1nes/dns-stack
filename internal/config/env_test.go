package config

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.env")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadKeysOnlyReturnsRequested(t *testing.T) {
	path := write(t, "ROLE=cn-resolver\nDOH_PATH=/fab02deadbeef/dns-query\nSECRET=hunter2\n")
	got := ReadKeys(path, "ROLE", "DOH_PATH")
	if got["ROLE"] != "cn-resolver" {
		t.Fatalf("ROLE = %q", got["ROLE"])
	}
	if got["DOH_PATH"] != "/fab02deadbeef/dns-query" {
		t.Fatalf("DOH_PATH = %q", got["DOH_PATH"])
	}
	if _, ok := got["SECRET"]; ok {
		t.Fatal("未请求的键不应出现在结果里")
	}
}

func TestReadKeysSkipsCommentsAndBlanks(t *testing.T) {
	path := write(t, "\n# DOH_PATH=/should-not-win\n\n  DOH_PATH = /real  \n")
	if got := ReadKeys(path, "DOH_PATH")["DOH_PATH"]; got != "/real" {
		t.Fatalf("DOH_PATH = %q，注释行不该生效、空白该剔除", got)
	}
}

func TestReadKeysKeepsValueWithEquals(t *testing.T) {
	path := write(t, "PANEL_CORS_ORIGINS=https://a.example.com?x=1\n")
	if got := ReadKeys(path, "PANEL_CORS_ORIGINS")["PANEL_CORS_ORIGINS"]; got != "https://a.example.com?x=1" {
		t.Fatalf("值里的 = 被截断了: %q", got)
	}
}

func TestReadKeysMissingFileReturnsEmpty(t *testing.T) {
	if got := ReadKeys(filepath.Join(t.TempDir(), "absent"), "ROLE"); len(got) != 0 {
		t.Fatalf("文件缺失应返回空表，得到 %v", got)
	}
}
