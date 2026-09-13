package selfcheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/config"
	"github.com/dns-stack/dns-stack/internal/stack"
)

const (
	backupBudget      = 48 * time.Hour
	geoipBudget       = 60 * 24 * time.Hour
	conntrackWarnPct  = 60
	conntrackFailPct  = 80
	establishedBudget = 86400
	defaultDoHPath    = "/dns-query"
)

func checkBackupFreshness(opt Options, report *Report, now time.Time) {
	c := &checker{report: report, group: "运维与恢复"}
	dir := "/var/backups/dns-stack"
	entries, err := os.ReadDir(dir)
	if err != nil {
		c.skip("最近一次备份", "读不到 %s", dir)
		return
	}
	var newest time.Time
	count := 0
	for _, e := range entries {
		if e.IsDir() || !strings.Contains(e.Name(), ".tar.zst") || strings.HasSuffix(e.Name(), ".sha256") {
			continue
		}
		count++
		if info, err := e.Info(); err == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	if count == 0 {
		c.warn("最近一次备份", "没有任何备份文件——手动跑一次: sudo dns-stack backup")
		return
	}
	age := now.Sub(newest)
	if age > backupBudget {
		c.warn("最近一次备份", "已是 %s 前(共 %d 个)——检查 dns-stack-maintenance.timer", humanAge(age), count)
		return
	}
	c.ok("最近一次备份", "%s前，共 %d 个可回滚版本", humanAge(age), count)
}

func checkEntrypoints(ctx context.Context, opt Options, report *Report) {
	if opt.Role != stack.RoleCNResolver {
		return
	}
	c := &checker{report: report, group: "对外入口"}
	keys := config.ReadKeys(opt.ConfigFile, "DOH_PATH", "DOH_PORT", "DOT_PORT")
	dohPath := keys["DOH_PATH"]
	if dohPath == "" {
		dohPath = defaultDoHPath
	}
	dohPort := keys["DOH_PORT"]
	if dohPort == "" {
		dohPort = "443"
	}
	dotPort := keys["DOT_PORT"]
	if dotPort == "" {
		dotPort = "853"
	}

	if out, err := exec.CommandContext(ctx, selfPath(), "doh-probe",
		"--name", "www.taobao.com", "--path", dohPath, "--port", dohPort).Output(); err != nil {
		c.fail("DoH 入口", "探针执行失败: %v", err)
	} else if strings.TrimSpace(string(out)) != "ok" {
		c.fail("DoH 入口", "端口 %s 无响应——检查证书与 mosproxy", dohPort)
	} else {
		c.ok("DoH 入口", "端口 %s 响应正常", dohPort)
	}

	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", "127.0.0.1:"+dotPort,
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		c.fail("DoT 入口", "%s/TCP 握手失败: %v——检查 mosproxy dot-in 配置", dotPort, err)
	} else {
		conn.Close()
		c.ok("DoT 入口", "%s/TCP TLS 握手正常", dotPort)
	}

	if dohPath == defaultDoHPath {
		c.warn("DoH 私密路径",
			"仍在默认路径 %s，等于对外开放公共解析器——改: sudo dns-stack doh-path --rotate", defaultDoHPath)
	} else {
		c.ok("DoH 私密路径", "已启用非默认路径")
	}
}

func checkSecretsPermissions(opt Options, report *Report) {
	c := &checker{report: report, group: "安全边界"}
	dir := "/etc/dns-stack/secrets"
	info, err := os.Stat(dir)
	if err != nil {
		c.skip("secrets 目录权限", "读不到 %s", dir)
		return
	}
	mode := info.Mode().Perm()
	if mode != 0o700 && mode != 0o710 {
		c.fail("secrets 目录权限", "当前 %04o，应为 0700 或 0710", mode)
	} else {
		c.ok("secrets 目录权限", "%04o", mode)
	}
	panelDir := filepath.Join(dir, "panel")
	entries, err := os.ReadDir(panelDir)
	if err != nil {
		return
	}
	var loose []string
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || e.IsDir() {
			continue
		}
		if info.Mode().Perm() != 0o400 {
			loose = append(loose, fmt.Sprintf("%s(%04o)", e.Name(), info.Mode().Perm()))
		}
	}
	if len(loose) > 0 {
		c.fail("面板私有文件权限", "以下文件不是 0400: %s", strings.Join(loose, " "))
		return
	}
	c.ok("面板私有文件权限", "%d 个文件均为 0400", len(entries))
}

func checkConntrack(opt Options, report *Report) {
	if opt.Role != stack.RoleCNResolver {
		return
	}
	c := &checker{report: report, group: "连接跟踪水位"}
	max := readProcInt("/proc/sys/net/netfilter/nf_conntrack_max")
	cur := readProcInt("/proc/sys/net/netfilter/nf_conntrack_count")
	if max <= 0 || cur < 0 {
		c.skip("conntrack 水位", "读不到计数——内核未加载 nf_conntrack 或无 /proc 访问权")
	} else {
		pct := cur * 100 / max
		switch {
		case pct >= conntrackFailPct:
			c.fail("conntrack 水位",
				"%d%% (%d/%d)——接近表满，满了就静默丢包；先查 nf_conntrack_tcp_timeout_established 再考虑放大 max",
				pct, cur, max)
		case pct >= conntrackWarnPct:
			c.warn("conntrack 水位", "%d%% (%d/%d)——留意增长趋势", pct, cur, max)
		default:
			c.ok("conntrack 水位", "%d%% (%d/%d)", pct, cur, max)
		}
	}
	established := readProcInt("/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established")
	switch {
	case established <= 0:
		c.skip("TCP established 超时", "读不到该参数")
	case established > establishedBudget:
		c.warn("TCP established 超时",
			"%ds(内核默认 5 天)——异常断开的 DoH/DoT 连接会长期占用表项，见 docs/sysctl-cn.conf", established)
	default:
		c.ok("TCP established 超时", "已收紧到 %ds", established)
	}
}

func readProcInt(path string) int {
	body, err := os.ReadFile(path)
	if err != nil {
		return -1
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(body)))
	if err != nil {
		return -1
	}
	return v
}

func checkGeoIPFreshness(opt Options, report *Report, now time.Time) {
	c := &checker{report: report, group: "归属库"}
	asn := filepath.Join(opt.StateDir, "geoip", "GeoLite2-ASN.mmdb")
	age, ok := fileAge(asn, now)
	if !ok {
		c.warn("ASN 归属库",
			"未安装——面板与 dns-stack test 不显示运营商；跑 dns-stack routing-data --only geoip --force")
		return
	}
	if age > geoipBudget {
		c.warn("ASN 归属库", "已 %s 未更新——检查 dns-stack-routing-data.timer", humanAge(age))
	} else {
		c.ok("ASN 归属库", "%s前更新", humanAge(age))
	}
	if _, ok := fileAge(filepath.Join(opt.StateDir, "geoip", "GeoLite2-City.mmdb"), now); ok {
		c.ok("City 归属库", "省份标注可用")
	} else {
		c.warn("City 归属库", "缺失——运营商识别不受影响，省份标注会减少")
	}
}

func checkPanel(ctx context.Context, opt Options, report *Report) {
	c := &checker{report: report, group: "管理面板"}
	listen := config.ReadKeys(opt.ConfigFile, "PANEL_LISTEN")["PANEL_LISTEN"]
	if listen == "" {
		listen = "127.0.0.1:8080"
	}
	port := listen
	if idx := strings.LastIndex(listen, ":"); idx >= 0 {
		port = listen[idx+1:]
	}
	if _, err := strconv.Atoi(port); err != nil {
		port = "8080"
	}
	public := !strings.HasPrefix(listen, "127.") &&
		!strings.HasPrefix(listen, "localhost") && !strings.HasPrefix(listen, "[::1]")
	scheme := "http"
	if public {
		scheme = "https"
	}
	base := fmt.Sprintf("%s://127.0.0.1:%s", scheme, port)
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	status := func(path string) int {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			return 0
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if code := status("/api/health"); code == 0 {
		c.fail("面板可达", "%s 无响应——journalctl -u dns-stack-panel", base)
		return
	}
	c.ok("面板可达", "%s 健康检查通过", base)

	code := status("/api/overview")
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden:
		c.ok("未登录请求被拒绝", "HTTP %d", code)
	case http.StatusOK:
		if public {
			c.fail("未登录请求被拒绝", "面板对公网开放却能匿名读数据接口(HTTP 200)")
		} else {
			c.warn("未登录请求被拒绝", "回环监听下匿名可读(HTTP 200)——对外开放前必须先设密码")
		}
	default:
		c.warn("未登录请求被拒绝", "HTTP %d，判据无法下结论", code)
	}
	if public {
		if _, err := os.Stat("/etc/dns-stack/secrets/panel/auth.json"); err != nil {
			c.fail("公网面板已设密码", "面板对公网开放但未设密码——sudo dns-stack panel-password")
		} else {
			c.ok("公网面板已设密码", "auth.json 存在")
		}
	}
}

func selfPath() string {
	if path, err := os.Executable(); err == nil {
		return path
	}
	return "/opt/dns-stack/bin/dns-stack-go"
}
