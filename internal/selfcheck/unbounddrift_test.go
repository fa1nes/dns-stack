package selfcheck

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/dns-stack/dns-stack/internal/stack"
	"github.com/dns-stack/dns-stack/unbound"
)

func TestTemplateSettingsReadsOnlySingleValuedServerKeys(t *testing.T) {
	body := "\nserver:\n    interface: 127.0.0.1@5335\n    do-ip6: yes\n" +
		"    harden-glue: yes   # trailing\n    identity: \"dns\"\n{{CN_WG_INTERFACE}}\n" +
		"    do-ip6: no\n    msg-cache-size: 128m\n\nremote-control:\n    control-port: 8953\n"
	got := map[string]string{}
	for _, s := range templateSettings(body) {
		got[s.key] = s.value
	}
	want := map[string]string{"do-ip6": "no", "harden-glue": "yes", "identity": "dns", "msg-cache-size": "128m"}
	if len(got) != len(want) {
		t.Fatalf("解析出 %v，期望 %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q，期望 %q（Unbound 同一个键以最后一次为准）", k, got[k], v)
		}
	}
}

func runningFromTemplate() map[string]string {
	out := map[string]string{}
	for _, s := range templateSettings(unbound.Template) {
		out[s.key] = unboundMemSize(s.value)
	}
	return out
}

func driftReport(t *testing.T, running map[string]string) Result {
	t.Helper()
	saved := unboundOption
	t.Cleanup(func() { unboundOption = saved })
	unboundOption = func(_ context.Context, key string) (string, error) {
		value, ok := running[key]
		if !ok {
			return "error unknown option", errors.New("exit status 1")
		}
		return value, nil
	}
	var report Report
	checkUnboundDrift(context.Background(), Options{Role: stack.RoleCNResolver}, &report)
	if len(report.Results) != 1 {
		t.Fatalf("期望 1 条结果，得到 %v", report.Results)
	}
	return report.Results[0]
}

func TestUnboundDriftFlagsARunningValueThatLeftTheTemplate(t *testing.T) {
	running := runningFromTemplate()
	if running["do-ip6"] != "no" || running["msg-cache-size"] != "134217728" {
		t.Fatalf("模板读法不对：do-ip6=%q msg-cache-size=%q", running["do-ip6"], running["msg-cache-size"])
	}
	running[unbound.ServeExpiredTTL] = "1209600"
	delete(running, "client-subnet-always-forward")

	if got := driftReport(t, running); got.Level != LevelOK {
		t.Fatalf("运行值与模板一致、面板调过 TTL、个别键读不到时应当通过，得到 %s：%s", got.Level, got.Detail)
	}

	running["do-ip6"] = "yes"
	got := driftReport(t, running)
	if got.Level != LevelFail || !strings.Contains(got.Detail, "do-ip6") {
		t.Fatalf("CN 没有 IPv6 路由却开着 do-ip6，Unbound 会把发送预算耗在不可达的地址上直到 SERVFAIL"+
			"（2026-10-01 pool.ntp.org 占了全部失败的 43%%）；这里应当报警，得到 %s：%s", got.Level, got.Detail)
	}
	if strings.Contains(got.Detail, unbound.ServeExpiredTTL) {
		t.Errorf("serve-expired-ttl 归面板调，不能算漂移：%s", got.Detail)
	}
}

func TestUnboundDriftAgainstARealGetOptionDump(t *testing.T) {
	body, err := os.ReadFile("testdata/unbound-get-option.tsv")
	if err != nil {
		t.Fatal(err)
	}
	running := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		key, value, _ := strings.Cut(line, "\t")
		if !strings.HasPrefix(value, "error") {
			running[key] = value
		}
	}
	got := driftReport(t, running)
	if got.Level != LevelOK || !strings.Contains(got.Detail, "，1 项这一版") {
		t.Fatalf("2026-10-01 国内节点修好 do-ip6 之后的真实输出应当一致、只有 client-subnet-always-forward 读不到，"+
			"得到 %s：%s——多半是运行值的写法（字节数、去引号）和模板没对齐", got.Level, got.Detail)
	}
	running["do-ip6"] = "yes"
	if got := driftReport(t, running); got.Level != LevelFail || strings.Count(got.Detail, "运行中是") != 1 {
		t.Fatalf("只改 do-ip6 应当恰好报出这一项，得到 %s：%s", got.Level, got.Detail)
	}
}
