package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dns-stack/dns-stack/internal/access"
)

type fakeUnbound struct {
	calls     []string
	checkFail bool
}

func (f *fakeUnbound) env(t *testing.T) localRecordEnv {
	dir := t.TempDir()
	return localRecordEnv{
		store:    access.Store{StateDir: dir},
		confPath: filepath.Join(dir, "dns-stack-local.conf"),
		out:      &strings.Builder{},
		run: func(_ context.Context, name string, args ...string) (string, error) {
			f.calls = append(f.calls, strings.Join(append([]string{name}, args...), " "))
			if name == "unbound-checkconf" && f.checkFail {
				return "syntax error", errors.New("exit 1")
			}
			return "ok", nil
		},
		flush: func(_ context.Context, name string) error {
			f.calls = append(f.calls, "flush "+name)
			return nil
		},
	}
}

func TestLocalRecordAddPushesToRunningUnboundWithoutReload(t *testing.T) {
	fake := &fakeUnbound{}
	env := fake.env(t)
	if err := env.add(context.Background(), "nas.home.arpa", "A", "192.168.1.2"); err != nil {
		t.Fatal(err)
	}
	conf, err := os.ReadFile(env.confPath)
	if err != nil || !strings.Contains(string(conf), "nas.home.arpa. 300 IN A 192.168.1.2") {
		t.Fatalf("配置没写出: %v %s", err, conf)
	}
	joined := strings.Join(fake.calls, "\n")
	for _, want := range []string{"unbound-checkconf", "local_data_remove nas.home.arpa",
		"local_data nas.home.arpa. 300 IN A 192.168.1.2", "flush nas.home.arpa"} {
		if !strings.Contains(joined, want) {
			t.Errorf("缺少调用 %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "reload") {
		t.Errorf("本地记录不该重载 Unbound（会清掉 ECS 缓存）:\n%s", joined)
	}
}

func TestLocalRecordRemoveReappliesTheRestOfTheName(t *testing.T) {
	fake := &fakeUnbound{}
	env := fake.env(t)
	ctx := context.Background()
	_ = env.add(ctx, "nas.home.arpa", "A", "192.168.1.2")
	_ = env.add(ctx, "nas.home.arpa", "AAAA", "fd00::2")
	fake.calls = nil
	if err := env.remove(ctx, "nas.home.arpa", "A", ""); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(fake.calls, "\n")
	if !strings.Contains(joined, "local_data nas.home.arpa. 300 IN AAAA fd00::2") ||
		strings.Contains(joined, "IN A 192.168.1.2") {
		t.Fatalf("删 A 后应只把 AAAA 推回去:\n%s", joined)
	}
}

func TestLocalRecordBadConfigRestoresTheOldFileAndList(t *testing.T) {
	fake := &fakeUnbound{}
	env := fake.env(t)
	ctx := context.Background()
	if err := env.add(ctx, "nas.home.arpa", "A", "192.168.1.2"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(env.confPath)
	fake.checkFail = true
	if err := env.add(ctx, "tv.home.arpa", "A", "192.168.1.3"); err == nil {
		t.Fatal("checkconf 不过应该报错")
	}
	after, _ := os.ReadFile(env.confPath)
	if string(after) != string(before) {
		t.Fatalf("配置没换回:\n%s", after)
	}
	records, _ := env.store.LocalRecords()
	if len(records) != 1 {
		t.Fatalf("名单也应撤回，剩 %v", records)
	}
}

func TestLocalRecordRefusesNamesAnotherListAnswersFirst(t *testing.T) {
	fake := &fakeUnbound{}
	env := fake.env(t)
	if err := os.WriteFile(filepath.Join(env.store.StateDir, access.RouteHKFile), []byte("example.org\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := env.add(context.Background(), "www.example.org", "A", "1.2.3.4"); err == nil ||
		!strings.Contains(err.Error(), "香港解析名单") {
		t.Fatalf("应拒绝被香港名单截走的名字: %v", err)
	}
}
