package rulesync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeRemote struct {
	files  map[string]string
	errors map[string]error
}

func bundleAt(gen int64, cn, gfw, cnCIDR, polluted string) map[string]string {
	head := fmt.Sprintf("# generated-at: %d\n", gen)
	return map[string]string{
		FileCN:       head + cn,
		FileGFW:      head + gfw,
		FileCNCIDR:   head + cnCIDR,
		FilePolluted: head + polluted,
	}
}

func newHarness(t *testing.T, sources map[string]map[string]string) (Options, *int, *int) {
	t.Helper()
	state := t.TempDir()
	reloads, healths := 0, 0
	var names []string
	for name := range sources {
		names = append(names, name)
	}
	opt := Options{
		StateDir: state,
		Sources:  names,
		Now:      func() time.Time { return time.Unix(1757000000, 0) },
		Fetch: func(ctx context.Context, url string) ([]byte, error) {
			for src, files := range sources {
				if !strings.HasPrefix(url, src+"/") {
					continue
				}
				body, ok := files[strings.TrimPrefix(url, src+"/")]
				if !ok {
					return nil, fmt.Errorf("404")
				}
				return []byte(body), nil
			}
			return nil, fmt.Errorf("no such source")
		},
		Reload: func(ctx context.Context) error { reloads++; return nil },
		Health: func(ctx context.Context) error { healths++; return nil },
	}
	return opt, &reloads, &healths
}

func read(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(body)
}

func seed(t *testing.T, opt Options, gen int64, files map[string]string) {
	t.Helper()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(opt.StateDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(opt.syncDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	opt.recordVersion(gen)
}

func TestSyncAppliesAndReloads(t *testing.T) {
	opt, reloads, healths := newHarness(t, map[string]map[string]string{
		"https://a.test": bundleAt(100, "qq.com\nbaidu.com\n", "google.com\n", "1.0.0.0/8\n", "10.0.0.0/8\n"),
	})
	res, err := Sync(context.Background(), opt)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if !res.Applied || res.GeneratedAt != 100 {
		t.Fatalf("应当应用版本 100，得到 %+v", res)
	}
	if *reloads != 1 || *healths != 1 {
		t.Errorf("reload=%d health=%d，各应为 1", *reloads, *healths)
	}
	if got := read(t, filepath.Join(opt.StateDir, FileCN)); got != "baidu.com\nqq.com\n" {
		t.Errorf("cn.txt 应被清洗为排序去重的纯域名，得到 %q", got)
	}
	if got := strings.TrimSpace(read(t, opt.lastGenPath())); got != "100" {
		t.Errorf("last-generated-at = %q", got)
	}
}

func TestSyncRejectsSourceWhoseFilesDisagreeOnVersion(t *testing.T) {
	files := bundleAt(100, "qq.com\n", "google.com\n", "1.0.0.0/8\n", "10.0.0.0/8\n")
	files[FileGFW] = "# generated-at: 99\ngoogle.com\n"
	opt, reloads, _ := newHarness(t, map[string]map[string]string{"https://a.test": files})
	res, err := Sync(context.Background(), opt)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if res.Applied || *reloads != 0 {
		t.Fatalf("四文件版本不一致的来源必须整体拒绝，得到 %+v", res)
	}
}

func TestSyncPrefersTheNewestSource(t *testing.T) {
	opt, _, _ := newHarness(t, map[string]map[string]string{
		"https://old.test": bundleAt(100, "qq.com\n", "google.com\n", "1.0.0.0/8\n", "10.0.0.0/8\n"),
		"https://new.test": bundleAt(200, "qq.com\nweibo.com\n", "google.com\n", "1.0.0.0/8\n", "10.0.0.0/8\n"),
	})
	res, err := Sync(context.Background(), opt)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if res.GeneratedAt != 200 || res.Source != "https://new.test" {
		t.Fatalf("应选版本最高的来源，得到 %+v", res)
	}
}

func TestSyncSkipsStaleRemote(t *testing.T) {
	opt, reloads, _ := newHarness(t, map[string]map[string]string{
		"https://a.test": bundleAt(50, "qq.com\n", "google.com\n", "1.0.0.0/8\n", "10.0.0.0/8\n"),
	})
	seed(t, opt, 100, map[string]string{FileCN: "qq.com\nweibo.com\n"})
	res, err := Sync(context.Background(), opt)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if res.Applied || *reloads != 0 {
		t.Fatalf("远端旧于本机时不该应用，得到 %+v", res)
	}
}

func TestSyncRefusesSameVersionWithDifferentContent(t *testing.T) {
	opt, reloads, _ := newHarness(t, map[string]map[string]string{
		"https://a.test": bundleAt(100, "qq.com\nweibo.com\ndouban.com\n", "google.com\n", "1.0.0.0/8\n", "10.0.0.0/8\n"),
	})
	seed(t, opt, 100, map[string]string{
		FileCN:       "aaa.com\nbbb.com\nccc.com\n",
		FileGFW:      "google.com\n",
		FileCNCIDR:   "1.0.0.0/8\n",
		FilePolluted: "10.0.0.0/8\n",
	})
	res, err := Sync(context.Background(), opt)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if res.Applied || *reloads != 0 {
		t.Fatalf("同版本号不同内容必须拒绝，得到 %+v", res)
	}
	if !strings.Contains(res.Reason, "拒绝覆盖") {
		t.Errorf("拒绝理由应说明冲突，得到 %q", res.Reason)
	}
}

func TestShrinkGuardHoldsTheLineUnlessForced(t *testing.T) {
	var old strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&old, "host%02d.example.com\n", i)
	}
	for _, c := range []struct {
		label  string
		remote string
	}{
		{"降为空集", ""},
		{"骤降过半", "host01.example.com\nhost02.example.com\n"},
	} {
		opt, reloads, _ := newHarness(t, map[string]map[string]string{
			"https://a.test": bundleAt(200, c.remote, "google.com\n", "1.0.0.0/8\n", "10.0.0.0/8\n"),
		})
		seed(t, opt, 100, map[string]string{
			FileCN: old.String(), FileGFW: "google.com\n",
			FileCNCIDR: "1.0.0.0/8\n", FilePolluted: "10.0.0.0/8\n",
		})
		res, err := Sync(context.Background(), opt)
		if err != nil {
			t.Fatalf("%s: %v", c.label, err)
		}
		if res.Applied || *reloads != 0 {
			t.Errorf("%s 应被骤降保护拦下，得到 %+v", c.label, res)
		}

		forced := opt
		forced.Force = true
		res, err = Sync(context.Background(), forced)
		if err != nil {
			t.Fatalf("%s --force: %v", c.label, err)
		}
		if !res.Applied {
			t.Errorf("%s 在 --force 下应当放行，得到 %+v", c.label, res)
		}
	}
}

func TestFailedReloadRestoresTheWholeBundle(t *testing.T) {
	for _, c := range []struct {
		label  string
		reload error
		health error
	}{
		{"reload 失败", fmt.Errorf("mosproxy 挂了"), nil},
		{"健康检查失败", nil, fmt.Errorf("递归不回答")},
	} {
		opt, _, _ := newHarness(t, map[string]map[string]string{
			"https://a.test": bundleAt(200, "new1.com\nnew2.com\n", "google.com\n", "1.0.0.0/8\n", "10.0.0.0/8\n"),
		})
		opt.Reload = func(context.Context) error { return c.reload }
		opt.Health = func(context.Context) error { return c.health }
		seed(t, opt, 100, map[string]string{
			FileCN: "old1.com\nold2.com\n", FileGFW: "google.com\n",
			FileCNCIDR: "1.0.0.0/8\n", FilePolluted: "10.0.0.0/8\n",
		})
		if _, err := Sync(context.Background(), opt); err == nil {
			t.Fatalf("%s 应当报错", c.label)
		}
		if got := read(t, filepath.Join(opt.StateDir, FileCN)); got != "old1.com\nold2.com\n" {
			t.Errorf("%s 之后 cn.txt 应恢复为旧内容，得到 %q", c.label, got)
		}
		if got := strings.TrimSpace(read(t, opt.lastGenPath())); got != "100" {
			t.Errorf("%s 之后版本号不该推进，得到 %q", c.label, got)
		}
	}
}

func TestRollbackRestoresAndHoldsTheVersion(t *testing.T) {
	opt, _, _ := newHarness(t, map[string]map[string]string{
		"https://a.test": bundleAt(200, "new1.com\nnew2.com\n", "google.com\n", "1.0.0.0/8\n", "10.0.0.0/8\n"),
	})
	opt.HistoryKeep = 3
	seed(t, opt, 100, map[string]string{
		FileCN: "old1.com\nold2.com\n", FileGFW: "google.com\n",
		FileCNCIDR: "1.0.0.0/8\n", FilePolluted: "10.0.0.0/8\n",
	})
	if res, err := Sync(context.Background(), opt); err != nil || !res.Applied {
		t.Fatalf("首次同步应成功: %+v %v", res, err)
	}
	if err := Rollback(context.Background(), opt); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if got := read(t, filepath.Join(opt.StateDir, FileCN)); got != "old1.com\nold2.com\n" {
		t.Fatalf("回滚后应是旧内容，得到 %q", got)
	}
	if got := strings.TrimSpace(read(t, opt.holdPath())); got != "200" {
		t.Fatalf("回滚保持版本应为 200，得到 %q", got)
	}
	res, err := Sync(context.Background(), opt)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if res.Applied {
		t.Fatal("回滚保持期内，同版本的远端规则不该被重新装回来")
	}
}

func TestSyncRejectsOverlapBetweenCNAndPollutedCIDR(t *testing.T) {
	opt, reloads, _ := newHarness(t, map[string]map[string]string{
		"https://a.test": bundleAt(100, "qq.com\n", "google.com\n", "1.0.0.0/8\n", "1.2.3.0/24\n"),
	})
	res, err := Sync(context.Background(), opt)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if res.Applied || *reloads != 0 {
		t.Fatalf("CN 与污染 CIDR 重叠的规则包必须拒绝，得到 %+v", res)
	}
}

func TestSyncRejectsCNDomainShadowedByGFWParent(t *testing.T) {
	opt, reloads, _ := newHarness(t, map[string]map[string]string{
		"https://a.test": bundleAt(100, "cn.example.com\n", "example.com\n", "1.0.0.0/8\n", "10.0.0.0/8\n"),
	})
	res, err := Sync(context.Background(), opt)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if res.Applied || *reloads != 0 {
		t.Fatalf("CN 子域被 GFW 父规则覆盖时必须拒绝，得到 %+v", res)
	}
}

func TestLocalPollutedEvidenceSurvivesSync(t *testing.T) {
	opt, _, _ := newHarness(t, map[string]map[string]string{
		"https://a.test": bundleAt(100, "qq.com\n", "google.com\n", "1.0.0.0/8\n", "10.0.0.0/8\n"),
	})
	if err := os.MkdirAll(opt.syncDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opt.localIPs(), []byte("93.46.8.89\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Sync(context.Background(), opt); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	got := read(t, filepath.Join(opt.StateDir, FilePolluted))
	if !strings.Contains(got, "93.46.8.89/32") {
		t.Fatalf("本机采集的污染 IP 应并入 polluted-ip-cidr.txt，得到 %q", got)
	}
	if !strings.Contains(got, "10.0.0.0/8") {
		t.Fatalf("远端污染段应保留，得到 %q", got)
	}
	if remote := read(t, opt.remoteSnapshot()); strings.Contains(remote, "93.46.8.89") {
		t.Fatal("远端快照不该被本机证据污染，否则下次同版本比对会永远冲突")
	}
}
