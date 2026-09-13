package rulesync

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dns-stack/dns-stack/internal/cdnrules"
)

func cdnBody(gen int64, provider string, nets ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# schema: %s\n# generated-at: %d\n# prefixes: %d\n", cdnrules.Schema, gen, len(nets))
	fmt.Fprintf(&b, "P\t%s\t%s\n", provider, provider)
	fmt.Fprintf(&b, "D\t%s\t%s.test\n", provider, provider)
	for _, n := range nets {
		fmt.Fprintf(&b, "N\t%s\toff\t%s\n", provider, n)
	}
	return b.String()
}

func cdnHarness(t *testing.T, sources map[string]string) Options {
	t.Helper()
	var names []string
	for name := range sources {
		names = append(names, name)
	}
	return Options{
		StateDir: t.TempDir(),
		Sources:  names,
		Now:      func() time.Time { return time.Unix(1757000000, 0) },
		Fetch: func(ctx context.Context, url string) ([]byte, error) {
			for src, body := range sources {
				if url == src+"/"+FileCDNDirect {
					return []byte(body), nil
				}
			}
			return nil, fmt.Errorf("404")
		},
	}
}

func TestSyncCDNAppliesAndIsIdempotent(t *testing.T) {
	opt := cdnHarness(t, map[string]string{"https://a.test": cdnBody(100, "fastly", "151.101.0.0/16")})
	res, err := SyncCDN(context.Background(), opt)
	if err != nil || !res.Applied {
		t.Fatalf("首次同步应落盘: %+v %v", res, err)
	}
	if _, err := os.Stat(CDNPath(opt.StateDir)); err != nil {
		t.Fatalf("规则集未落盘: %v", err)
	}
	res, err = SyncCDN(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied {
		t.Fatalf("内容未变时不该重复落盘，得到 %+v", res)
	}
}

func TestSyncCDNRejectsARulesetClaimingTestNet(t *testing.T) {
	opt := cdnHarness(t, map[string]string{
		"https://a.test": cdnBody(100, "evil", "192.0.2.0/24"),
	})
	res, err := SyncCDN(context.Background(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied {
		t.Fatal("宣称拥有 TEST-NET-1 的规则集必须被自检拦下")
	}
	if _, err := os.Stat(CDNPath(opt.StateDir)); err == nil {
		t.Fatal("被拒绝的规则集不该留在磁盘上")
	}
}

func TestSyncCDNRefusesSuddenShrinkUnlessForced(t *testing.T) {
	nets := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		nets = append(nets, fmt.Sprintf("10.%d.0.0/24", i))
	}
	opt := cdnHarness(t, map[string]string{"https://a.test": cdnBody(100, "fastly", nets...)})
	if res, err := SyncCDN(context.Background(), opt); err != nil || !res.Applied {
		t.Fatalf("首次同步应成功: %+v %v", res, err)
	}
	shrunk := cdnHarness(t, map[string]string{"https://a.test": cdnBody(200, "fastly", nets[:10]...)})
	shrunk.StateDir = opt.StateDir
	res, err := SyncCDN(context.Background(), shrunk)
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied {
		t.Fatalf("前缀数骤降应被拦下，得到 %+v", res)
	}
	shrunk.Force = true
	if res, err := SyncCDN(context.Background(), shrunk); err != nil || !res.Applied {
		t.Fatalf("--force 下应放行: %+v %v", res, err)
	}
}

func TestSyncCDNKeepsTheOldCopyWhenEverySourceFails(t *testing.T) {
	opt := cdnHarness(t, map[string]string{"https://a.test": cdnBody(100, "fastly", "151.101.0.0/16")})
	if _, err := SyncCDN(context.Background(), opt); err != nil {
		t.Fatal(err)
	}
	before := read(t, CDNPath(opt.StateDir))
	broken := opt
	broken.Fetch = func(context.Context, string) ([]byte, error) { return nil, fmt.Errorf("网络不可达") }
	res, err := SyncCDN(context.Background(), broken)
	if err != nil {
		t.Fatalf("来源全挂不该是错误，只是本轮无事可做: %v", err)
	}
	if res.Applied {
		t.Fatal("没有可用来源时不该声称应用了")
	}
	if after := read(t, CDNPath(opt.StateDir)); after != before {
		t.Fatal("来源全挂时必须保留旧规则集")
	}
}
