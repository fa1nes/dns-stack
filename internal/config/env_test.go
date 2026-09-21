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
	path := write(t, "ROLE=cn-resolver\nPUBLIC_IPV4=1.2.3.4\n")
	got := ReadKeys(path, "ROLE")
	if len(got) != 1 || got["ROLE"] != "cn-resolver" {
		t.Fatalf("ReadKeys = %v", got)
	}
}

func TestReadReturnsEverything(t *testing.T) {
	path := write(t, "ROLE=cn-resolver\nPUBLIC_IPV4=1.2.3.4\n")
	got := Read(path)
	if len(got) != 2 || got["PUBLIC_IPV4"] != "1.2.3.4" {
		t.Fatalf("Read = %v", got)
	}
}

func TestEveryReaderAgreesOnTheSameFile(t *testing.T) {
	cases := map[string]struct{ body, key, want string }{
		"普通":      {"ROLE=cn-resolver\n", "ROLE", "cn-resolver"},
		"双引号":     {"ROLE=\"cn-resolver\"\n", "ROLE", "cn-resolver"},
		"单引号":     {"ROLE='cn-resolver'\n", "ROLE", "cn-resolver"},
		"引号不成对":   {"ROLE=\"cn-resolver\n", "ROLE", "\"cn-resolver"},
		"前导空格":    {"   ROLE=cn-resolver\n", "ROLE", "cn-resolver"},
		"等号两侧空格":  {"ROLE = cn-resolver\n", "ROLE", "cn-resolver"},
		"注释掉的键":   {"#ROLE=offshore\nROLE=cn-resolver\n", "ROLE", "cn-resolver"},
		"值里有等号":   {"CDN_RULES_BASE=https://x/?a=b\n", "CDN_RULES_BASE", "https://x/?a=b"},
		"值里有井号":   {"DOH_PATH=/a#b/dns-query\n", "DOH_PATH", "/a#b/dns-query"},
		"空值":      {"PUBLIC_IPV6=\n", "PUBLIC_IPV6", ""},
		"只有注释和空行": {"\n# 说明\n", "ROLE", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			path := write(t, c.body)
			if got := Value(path, c.key); got != c.want {
				t.Errorf("Value = %q，期望 %q", got, c.want)
			}
			if got := ReadKeys(path, c.key)[c.key]; got != c.want {
				t.Errorf("ReadKeys = %q，期望 %q", got, c.want)
			}
			if got := Read(path)[c.key]; got != c.want {
				t.Errorf("Read = %q，期望 %q；三个入口读同一个文件必须给同一个答案——"+
					"面板和 helper 对 ROLE 的理解一旦分叉，角色闸门就会一边放行一边拒绝",
					got, c.want)
			}
		})
	}
}

func TestMissingFileReturnsEmpty(t *testing.T) {
	if got := Read(filepath.Join(t.TempDir(), "absent.env")); len(got) != 0 {
		t.Fatalf("读不到文件时应返回空表，实际 %v", got)
	}
}
