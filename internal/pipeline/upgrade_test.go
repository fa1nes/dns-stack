package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type fakeRelease struct {
	binary []byte
	sum    string
}

func newRelease(t *testing.T, version string) *fakeRelease {
	t.Helper()
	body := append([]byte("VERSION="+version+"\n"), bytes.Repeat([]byte{0}, upgradeMinBytes)...)
	digest := sha256.Sum256(body)
	return &fakeRelease{binary: body, sum: hex.EncodeToString(digest[:])}
}

func (r *fakeRelease) serve(t *testing.T) string {
	t.Helper()
	name := "/dns-stack-linux-" + runtime.GOARCH
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case name:
			_, _ = w.Write(r.binary)
		case name + ".sha256":
			_, _ = w.Write([]byte(r.sum + "  dns-stack-linux\n"))
		default:
			http.NotFound(w, req)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func readVersion(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(string(data), "\n")
	return strings.TrimPrefix(line, "VERSION="), nil
}

type upgradeFixture struct {
	binary  string
	backups string
	calls   []string
	failing map[string]bool
}

func newUpgradeFixture(t *testing.T, current string) *upgradeFixture {
	t.Helper()
	dir := t.TempDir()
	f := &upgradeFixture{binary: filepath.Join(dir, "bin", "dns-stack-go"), backups: filepath.Join(dir, "backups"), failing: map[string]bool{}}
	if err := os.MkdirAll(filepath.Dir(f.binary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.binary, []byte("VERSION="+current+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *upgradeFixture) options(base, current string, restart ...string) UpgradeOptions {
	return UpgradeOptions{
		Base: base, Binary: f.binary, BackupDir: f.backups, Current: current, Restart: restart,
		Now:       func() time.Time { return time.Date(2026, 10, 17, 22, 0, 0, 0, time.UTC) },
		VersionOf: readVersion,
		Settle:    time.Millisecond,
		Systemctl: func(_ context.Context, args ...string) error {
			f.calls = append(f.calls, strings.Join(args, " "))
			if args[0] == "is-active" && f.failing[args[len(args)-1]] {
				if v, _ := readVersion(f.binary); v != "old" {
					return errors.New("inactive")
				}
			}
			return nil
		},
	}
}

func testRuntime() *Runtime { return NewRuntime(Config{}, &bytes.Buffer{}) }

func TestUpgradeReplacesBackupsAndRestartsInOrder(t *testing.T) {
	rel := newRelease(t, "new")
	f := newUpgradeFixture(t, "old")
	res, err := Upgrade(context.Background(), testRuntime(), f.options(rel.serve(t), "old", "dns-stack-helper", "dns-stack-panel"))
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := readVersion(f.binary); v != "new" || !res.Changed || res.To != "new" {
		t.Fatalf("应换成新版本: %+v 现在是 %s", res, v)
	}
	if v, _ := readVersion(res.Backup); v != "old" || !strings.HasSuffix(res.Backup, "dns-stack-go.pre-20261017220000") {
		t.Fatalf("备份不对: %s %s", res.Backup, v)
	}
	if sidecar, err := os.ReadFile(f.binary + ".sha256"); err != nil || !strings.HasPrefix(string(sidecar), rel.sum) {
		t.Fatalf(".sha256 旁注应写新二进制的校验和: %q %v", sidecar, err)
	}
	want := "restart dns-stack-helper.service|restart dns-stack-panel.service|is-active --quiet dns-stack-helper.service|is-active --quiet dns-stack-panel.service"
	if got := strings.Join(f.calls, "|"); got != want {
		t.Fatalf("重启顺序不对:\n%s", got)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(f.binary), ".upgrade-*")); len(leftovers) != 0 {
		t.Fatalf("临时目录没清掉: %v", leftovers)
	}
}

func TestUpgradeSameVersionAndCheckTouchNothing(t *testing.T) {
	rel := newRelease(t, "same")
	base := rel.serve(t)
	f := newUpgradeFixture(t, "same")
	res, err := Upgrade(context.Background(), testRuntime(), f.options(base, "same", "dns-stack-panel"))
	if err != nil || res.Changed || len(f.calls) != 0 {
		t.Fatalf("同版本不该替换也不该重启: %+v %v %v", res, err, f.calls)
	}

	newer := newRelease(t, "newer")
	g := newUpgradeFixture(t, "same")
	opt := g.options(newer.serve(t), "same", "dns-stack-panel")
	opt.Check = true
	res, err = Upgrade(context.Background(), testRuntime(), opt)
	if err != nil || !res.Changed || res.To != "newer" || len(g.calls) != 0 {
		t.Fatalf("--check 应报告新版本但不动手: %+v %v %v", res, err, g.calls)
	}
	if v, _ := readVersion(g.binary); v != "same" {
		t.Fatal("--check 把二进制换掉了")
	}
}

func TestUpgradeRejectsChecksumMismatch(t *testing.T) {
	rel := newRelease(t, "new")
	rel.sum = strings.Repeat("0", 64)
	f := newUpgradeFixture(t, "old")
	if _, err := Upgrade(context.Background(), testRuntime(), f.options(rel.serve(t), "old", "dns-stack-panel")); err == nil {
		t.Fatal("校验和不符必须失败")
	}
	if v, _ := readVersion(f.binary); v != "old" || len(f.calls) != 0 {
		t.Fatalf("校验失败时不能碰现有二进制和服务: %s %v", v, f.calls)
	}
}

func TestUpgradeRollsBackWhenServiceDoesNotComeUp(t *testing.T) {
	rel := newRelease(t, "broken")
	f := newUpgradeFixture(t, "old")
	f.failing["dns-stack-panel.service"] = true
	res, err := Upgrade(context.Background(), testRuntime(), f.options(rel.serve(t), "old", "dns-stack-panel"))
	if err == nil || !res.Rollback {
		t.Fatalf("面板起不来应当回滚并报错: %+v %v", res, err)
	}
	if v, _ := readVersion(f.binary); v != "old" {
		t.Fatalf("回滚后应是旧二进制，现在是 %s", v)
	}
	if n := strings.Count(strings.Join(f.calls, "|"), "restart dns-stack-panel.service"); n != 2 {
		t.Fatalf("换回旧二进制后要再重启一次: %v", f.calls)
	}
}

func TestParseRestartOrdersAndRejects(t *testing.T) {
	got, err := ParseRestart("dns-stack-panel, dns-stack-helper.service,dns-stack-panel")
	if err != nil || strings.Join(got, ",") != "dns-stack-helper,dns-stack-panel" {
		t.Fatalf("应去重并按助手→面板排序: %v %v", got, err)
	}
	if _, err := ParseRestart("unbound"); err == nil {
		t.Fatal("unbound 不该由 upgrade 重启")
	}
}
