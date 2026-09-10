package cnauth

import (
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type stubGeo struct{ foreign map[string]bool }

func (s stubGeo) CountryOf(addr netip.Addr) (string, string, bool) {
	if s.foreign[addr.String()] {
		return "US", "美国 fixture", true
	}
	return "CN", "中国 fixture", true
}

type orphanLab struct {
	t   *testing.T
	dir string
	opt OrphanOptions
}

func newOrphanLab(t *testing.T) *orphanLab {
	t.Helper()
	l := &orphanLab{t: t, dir: t.TempDir()}
	l.put("ecs.conf", "    send-client-subnet: 10.0.0.0/24\n    send-client-subnet: 10.0.1.0/24\n    send-client-subnet: 192.0.2.0/30\n")
	l.put("direct4.txt", "10.0.0.0/23\n")
	l.put("cn-authority.txt", "203.0.113.0/30\n")
	l.put("shared-excluded.txt", "192.0.2.0\n192.0.2.1\n192.0.2.2\n192.0.2.3\n")
	l.opt = OrphanOptions{
		ECSConfPath:        l.at("ecs.conf"),
		Direct4Path:        l.at("direct4.txt"),
		CNAuthorityPath:    l.at("cn-authority.txt"),
		SharedExcludedPath: l.at("shared-excluded.txt"),
		AccumStatePath:     l.at("ecs-accum-state.tsv"),
		AccumTTL:           DefaultAccumTTL,
		MaxForeign:         0,
		Geo:                stubGeo{foreign: map[string]bool{"192.0.2.0": true, "8.8.8.8": true}},
		Now:                func() time.Time { return frozen },
	}
	return l
}

func (l *orphanLab) at(name string) string { return filepath.Join(l.dir, name) }

func (l *orphanLab) put(name, body string) {
	l.t.Helper()
	if err := os.WriteFile(l.at(name), []byte(body), 0o644); err != nil {
		l.t.Fatalf("写 %s 失败: %v", name, err)
	}
}

func (l *orphanLab) append(name, body string) {
	l.t.Helper()
	data, err := os.ReadFile(l.at(name))
	if err != nil {
		l.t.Fatalf("读 %s 失败: %v", name, err)
	}
	l.put(name, string(data)+body)
}

func (l *orphanLab) audit() (OrphanReport, error) {
	l.t.Helper()
	return AuditOrphans(l.opt)
}

func TestLegitimateSourcesAreNotOrphans(t *testing.T) {
	l := newOrphanLab(t)
	report, err := l.audit()
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !report.OK || len(report.Orphans) != 0 {
		t.Fatalf("direct4 / cn-authority / shared-excluded 覆盖的条目都不是孤儿，得到 %d 条: %+v",
			len(report.Orphans), report.Orphans)
	}
}

func TestForeignOrphanTripsTheThreshold(t *testing.T) {
	l := newOrphanLab(t)
	l.append("ecs.conf", "    send-client-subnet: 8.8.8.8/32\n")

	report, err := l.audit()
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if report.OK {
		t.Fatal("境外孤儿必须触发阈值失败——那是境外权威正在收中国 ECS 的信号")
	}
	if report.ForeignOrphans != 1 {
		t.Errorf("境外孤儿数应为 1，得到 %d", report.ForeignOrphans)
	}
}

func TestAccumulationWithinTTLIsNotAnOrphan(t *testing.T) {
	l := newOrphanLab(t)
	l.append("ecs.conf", "    send-client-subnet: 8.8.8.8/32\n")
	l.put("ecs-accum-state.tsv", "8.8.8.8/32\t"+unixText(frozen.Unix())+"\n")

	report, err := l.audit()
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !report.OK {
		t.Fatalf("TTL 内的累积保留是设计内的短期留存，不该计为孤儿: %+v", report.Orphans)
	}
	if report.AccumRetained != 1 {
		t.Errorf("累积保留计数应为 1，得到 %d", report.AccumRetained)
	}
}

func TestExpiredAccumulationBecomesAnOrphanAgain(t *testing.T) {
	l := newOrphanLab(t)
	l.append("ecs.conf", "    send-client-subnet: 8.8.8.8/32\n")
	l.put("ecs-accum-state.tsv",
		"8.8.8.8/32\t"+unixText(frozen.Unix()-int64(DefaultAccumTTL.Seconds())-3600)+"\n")

	report, err := l.audit()
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if report.OK {
		t.Fatal("过期的累积条目必须重新计入孤儿，否则它会永远赖在白名单里")
	}
	if report.AccumRetained != 0 {
		t.Errorf("过期条目不该算作累积保留，得到 %d", report.AccumRetained)
	}
	if !strings.Contains(report.AccumNote, "已过 TTL") {
		t.Errorf("说明里要点出有条目过期，得到 %q", report.AccumNote)
	}
}

func TestGapInSharedExcludedSurfacesAsOrphan(t *testing.T) {
	l := newOrphanLab(t)
	l.put("shared-excluded.txt", "192.0.2.0\n192.0.2.1\n192.0.2.2\n")

	report, err := l.audit()
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if report.OK {
		t.Fatal("共享排除清单出现缺口时，被它覆盖的 /30 就不再有来源，必须报成孤儿")
	}
}

func TestUnreadableAccumStateFailsClosed(t *testing.T) {
	l := newOrphanLab(t)
	l.append("ecs.conf", "    send-client-subnet: 8.8.8.8/32\n")
	if err := os.Mkdir(l.at("ecs-accum-state.tsv"), 0o755); err != nil {
		t.Fatalf("造不可读状态失败: %v", err)
	}
	report, err := l.audit()
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if report.OK {
		t.Fatal("累积状态读不到时必须 fail-closed，全部按真孤儿计——判据自身失效比结果为 0 更危险")
	}
	if !strings.Contains(report.AccumNote, "fail-closed") {
		t.Errorf("说明里要写明是 fail-closed，得到 %q", report.AccumNote)
	}
}

func TestEmptyWhitelistIsRefusedRatherThanReportedAsClean(t *testing.T) {
	l := newOrphanLab(t)
	l.put("ecs.conf", "server:\n")
	if _, err := l.audit(); err == nil {
		t.Fatal("白名单为空必须报错——「查不到孤儿」和「白名单读不出来」是两回事")
	}
}

func TestOrphanAuditRefusesEmptyDirect4(t *testing.T) {
	l := newOrphanLab(t)
	l.put("direct4.txt", "# 空\n")
	if _, err := l.audit(); err == nil {
		t.Fatal("direct4 为空时判断不了孤儿，必须报错而不是把整个白名单都算成孤儿")
	}
}

func unixText(value int64) string { return strconv.FormatInt(value, 10) }
