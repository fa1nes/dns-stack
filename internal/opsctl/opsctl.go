package opsctl

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/config"
	"github.com/dns-stack/dns-stack/internal/stack"

	_ "modernc.org/sqlite"
)

const (
	DefaultStateDir = "/var/lib/dns-stack"
	DefaultGoBin    = "/opt/dns-stack/bin/dns-stack-go"
	mosproxyReload  = "http://127.0.0.1:8888/ctl/reload"
	classifierLock  = "/run/lock/dns-stack-classifier.lock"
	panelAuthFile   = "/etc/dns-stack/secrets/panel/auth.json"
	archEpochFile   = "architecture-epoch"
)

type Ctl struct {
	StateDir   string
	ConfigFile string
	GoBin      string
	Out        io.Writer
	In         io.Reader
	AssumeYes  bool
	Now        func() time.Time
}

func New() *Ctl {
	return &Ctl{
		StateDir:   DefaultStateDir,
		ConfigFile: config.DefaultPath,
		GoBin:      DefaultGoBin,
		Out:        os.Stdout,
		In:         os.Stdin,
		Now:        time.Now,
	}
}

func (c *Ctl) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Ctl) Infof(format string, a ...any) { fmt.Fprintf(c.Out, "[信息] "+format+"\n", a...) }
func (c *Ctl) Okf(format string, a ...any)   { fmt.Fprintf(c.Out, "[成功] "+format+"\n", a...) }
func (c *Ctl) Warnf(format string, a ...any) { fmt.Fprintf(c.Out, "[警告] "+format+"\n", a...) }

func (c *Ctl) Role() string {
	role := config.ReadKeys(c.ConfigFile, "ROLE")["ROLE"]
	if role == "" {
		return "unknown"
	}
	return role
}

func (c *Ctl) requireRole(want string) error {
	if c.Role() == want {
		return nil
	}
	if want == stack.RoleCNResolver {
		return fmt.Errorf("该命令只适用于国内解析节点")
	}
	return fmt.Errorf("该命令只适用于规则构建节点")
}

func (c *Ctl) Confirm(prompt string) bool {
	if c.AssumeYes {
		return true
	}
	fmt.Fprintf(c.Out, "%s [y/N] ", prompt)
	reader := bufio.NewReader(c.In)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}

func (c *Ctl) state(parts ...string) string {
	return filepath.Join(append([]string{c.StateDir}, parts...)...)
}

func (c *Ctl) Run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = c.Out, c.Out, c.In
	return cmd.Run()
}

func (c *Ctl) Go(ctx context.Context, args ...string) error {
	return c.Run(ctx, c.GoBin, args...)
}

func (c *Ctl) systemctl(ctx context.Context, args ...string) error {
	return exec.CommandContext(ctx, "systemctl", args...).Run()
}

func (c *Ctl) unitActive(ctx context.Context, unit string) bool {
	return c.systemctl(ctx, "is-active", "--quiet", unit) == nil
}

func (c *Ctl) Reload(ctx context.Context) error {
	c.Infof("正在重载 mosproxy 域名表...")
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, mosproxyReload, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("重载失败，请确认 mosproxy 正在运行: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("重载失败(HTTP %d)，请确认 mosproxy 正在运行", resp.StatusCode)
	}
	c.Okf("域名表已重载")
	if c.Role() == stack.RoleCNResolver {
		if c.systemctl(ctx, "reload", "unbound.service") == nil {
			c.Okf("Unbound 已重载")
		}
	}
	return nil
}

func (c *Ctl) Restart(ctx context.Context) error {
	for _, unit := range []string{"mosproxy.service", "unbound.service"} {
		if err := c.systemctl(ctx, "restart", unit); err != nil {
			return fmt.Errorf("重启 %s 失败: %w", unit, err)
		}
	}
	c.Okf("已重启")
	return nil
}

func (c *Ctl) Logs(ctx context.Context, unit string) error {
	if unit == "" {
		unit = defaultLogUnit(c.Role())
	}
	return c.Run(ctx, "journalctl", "-u", unit+".service", "-n", "100", "--no-pager")
}

func defaultLogUnit(role string) string {
	if role == stack.RoleCNResolver {
		return "mosproxy"
	}
	return "unbound"
}

func (c *Ctl) CertCheck(ctx context.Context) error {
	return c.Go(ctx, "maintenance", "--check-cert")
}

func (c *Ctl) CertRenew(ctx context.Context) error {
	return c.Go(ctx, "maintenance", "--only", "renew-cert", "--force")
}

func (c *Ctl) RoutingStatus(ctx context.Context) error {
	if err := c.requireRole(stack.RoleCNResolver); err != nil {
		return err
	}
	return c.Go(ctx, "routing-setup", "status")
}

func (c *Ctl) RoutingRefresh(ctx context.Context) error {
	if err := c.requireRole(stack.RoleCNResolver); err != nil {
		return err
	}
	c.Infof("按依赖顺序重建分流数据(归属库 → 大陆网段 → 交叉校验 → anycast → 权威/ECS → 分片表)...")
	return c.Go(ctx, "routing-data", "--force")
}

func (c *Ctl) PanelPassword(ctx context.Context) error {
	password, err := readSecret(c.Out, c.In, "请输入新的面板密码(至少 12 位): ")
	if err != nil {
		return err
	}
	if len(password) < 12 {
		return fmt.Errorf("密码太短(至少 12 位)。面板能重启服务、导出含密钥的备份，值得一个强密码")
	}
	again, err := readSecret(c.Out, c.In, "请再输入一次: ")
	if err != nil {
		return err
	}
	if password != again {
		return fmt.Errorf("两次输入不一致")
	}
	cmd := exec.CommandContext(ctx, c.GoBin, "panel-auth", "set-password")
	cmd.Env = append(os.Environ(), "PW="+password)
	cmd.Stderr = c.Out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("写入密码失败: %w", err)
	}
	hardenPanelAuth()
	c.Okf("密码已设置(存的是 scrypt 哈希，不是明文)")
	c.Infof("改密码会让所有已登录会话立即失效")
	if c.systemctl(ctx, "restart", "dns-stack-panel") == nil {
		c.Okf("面板已重启")
	}
	return nil
}

func (c *Ctl) PanelResetTOTP(ctx context.Context) error {
	if _, err := os.Stat(panelAuthFile); err != nil {
		return fmt.Errorf("面板尚未设置密码，无二次认证可重置")
	}
	if !c.Confirm("即将关闭面板的二次认证(TOTP)，之后仅凭密码即可登录。确认继续？") {
		c.Warnf("已取消")
		return nil
	}
	out, err := exec.CommandContext(ctx, c.GoBin, "panel-auth", "disable-totp").Output()
	if err != nil {
		return fmt.Errorf("重置失败: %w", err)
	}
	hardenPanelAuth()
	if strings.Contains(string(out), "本就未启用") {
		c.Okf("二次认证本就未启用，未做改动")
	} else {
		c.Okf("二次认证已关闭，现在仅凭密码即可登录")
		c.Infof("建议登录后重新启用，并把新密钥存到可靠的地方")
	}
	if c.systemctl(ctx, "restart", "dns-stack-panel") == nil {
		c.Okf("面板已重启")
	}
	return nil
}

func hardenPanelAuth() {
	exec.Command("chown", "dns-stack-panel:dns-stack-panel", panelAuthFile).Run()
	os.Chmod(panelAuthFile, 0o400)
}

func (c *Ctl) openCollector() (*sql.DB, error) {
	path := c.state("collector.db")
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("找不到 %s", path)
	}
	return sql.Open("sqlite", path+"?_pragma=busy_timeout(10000)")
}

func (c *Ctl) ClearAudit(ctx context.Context) error {
	db, err := c.openCollector()
	if err != nil {
		return err
	}
	defer db.Close()
	var n int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log").Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		c.Okf("审计记录为空")
		return nil
	}
	if !c.Confirm(fmt.Sprintf("即将清空 %d 条审计记录，确认？", n)) {
		c.Warnf("已取消")
		return nil
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM audit_log"); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO audit_log(ts,actor,operation,args,ok,message) VALUES (?,?,?,?,?,?)`,
		c.now().Unix(), "cli", "audit_clear", "{}", 1,
		fmt.Sprintf("已清空 %d 条审计记录", n)); err != nil {
		return err
	}
	c.Okf("已清空 %d 条审计记录", n)
	return nil
}

func (c *Ctl) ClearDomains(ctx context.Context, arg string) error {
	db, err := c.openCollector()
	if err != nil {
		return err
	}
	defer db.Close()
	var total int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM domains").Scan(&total); err != nil {
		return err
	}
	if arg == "all" {
		if total == 0 {
			c.Okf("域名表已为空，无需清理")
			return nil
		}
		if !c.Confirm(fmt.Sprintf("即将清空全部 %d 个域名及其查询记录，确认？", total)) {
			c.Warnf("已取消")
			return nil
		}
		for _, stmt := range []string{"DELETE FROM domains", "DELETE FROM query_events", "VACUUM"} {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				return err
			}
		}
		c.Okf("已清空全部 %d 个域名与查询记录", total)
		return nil
	}
	days, err := strconv.Atoi(arg)
	if err != nil || days < 0 {
		return fmt.Errorf("参数需为天数或 all")
	}
	cutoff := c.now().AddDate(0, 0, -days).Unix()
	var n int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM domains WHERE last_seen_at < ?", cutoff).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		c.Okf("没有超过 %d 天未出现的域名，无需清理", days)
		c.Infof("  当前共 %d 个域名，全部在 %d 天内出现过", total, days)
		c.Infof("  如需清空全部统计重新开始：dns-stack clear-domains all")
		return nil
	}
	if !c.Confirm(fmt.Sprintf("即将清理 %d 个超过 %d 天未出现的域名及其记录(共 %d 个)，确认？", n, days, total)) {
		c.Warnf("已取消")
		return nil
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM domains WHERE last_seen_at < ?", cutoff); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM query_events WHERE ts < ?", cutoff); err != nil {
		return err
	}
	db.ExecContext(ctx, "VACUUM")
	c.Okf("已清理 %d 个陈旧域名，剩余 %d 个", n, total-n)
	return nil
}

func (c *Ctl) SetArchEpoch(ctx context.Context, arg string) error {
	if err := c.requireRole(stack.RoleCNResolver); err != nil {
		return err
	}
	ts := c.now().Unix()
	if arg != "" {
		parsed, err := strconv.ParseInt(arg, 10, 64)
		if err != nil || parsed <= 0 {
			return fmt.Errorf("时间戳必须是正整数")
		}
		ts = parsed
	}
	path := c.state(archEpochFile)
	if err := os.WriteFile(path, []byte(strconv.FormatInt(ts, 10)+"\n"), 0o644); err != nil {
		return err
	}
	c.Okf("架构基准已设为 %s；面板统计将只采用此后的数据",
		time.Unix(ts, 0).Format("2006-01-02 15:04:05"))
	return nil
}

func (c *Ctl) PurgeLegacy(ctx context.Context) error {
	if err := c.requireRole(stack.RoleCNResolver); err != nil {
		return err
	}
	body, err := os.ReadFile(c.state(archEpochFile))
	if err != nil {
		return fmt.Errorf("未设置架构基准，先执行: dns-stack set-arch-epoch")
	}
	epoch, err := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
	if err != nil || epoch <= 0 {
		return fmt.Errorf("未设置架构基准，先执行: dns-stack set-arch-epoch")
	}
	db, err := c.openCollector()
	if err != nil {
		return err
	}
	defer db.Close()
	var n int
	if err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM query_events WHERE ts < ?", epoch).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		c.Okf("没有早于基准的记录，无需清理")
		return nil
	}
	c.Warnf("将删除 %d 条早于 %s 的查询记录", n, time.Unix(epoch, 0).Format("2006-01-02 15:04:05"))
	c.Warnf("这些记录描述的是已退场的旧架构，无法追溯修正")
	if !c.Confirm("确认删除？") {
		c.Warnf("已取消")
		return nil
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM query_events WHERE ts < ?", epoch); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM domains WHERE last_seen_at < ?", epoch); err != nil {
		return err
	}
	db.ExecContext(ctx, "VACUUM")
	c.Okf("已清理 %d 条旧架构记录并压缩数据库", n)
	return nil
}

var keepRe = regexp.MustCompile(`^[0-9]+[dwm]$`)

func (c *Ctl) VacuumLogs(ctx context.Context, keep string) error {
	if keep == "" {
		keep = "7d"
	}
	if !keepRe.MatchString(keep) {
		return fmt.Errorf("保留期格式如 7d / 2w / 1m")
	}
	before := journalUsage(ctx)
	if !c.Confirm(fmt.Sprintf("即将删除 %s 之前的系统日志(当前占用 %s)，确认？", keep, before)) {
		c.Warnf("已取消")
		return nil
	}
	if err := c.Run(ctx, "journalctl", "--vacuum-time="+keep); err != nil {
		return err
	}
	c.Okf("日志已清理：%s → %s", before, journalUsage(ctx))
	return nil
}

func journalUsage(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "journalctl", "--disk-usage").Output()
	if err != nil {
		return "未知"
	}
	if m := regexp.MustCompile(`[0-9.]+[KMG]`).FindString(string(out)); m != "" {
		return m
	}
	return "未知"
}

func (c *Ctl) ListPackages() error {
	for _, spec := range []struct {
		label, dir, suffix string
	}{
		{"导出包", "/srv/dns-stack/export", ".tar.zst.age"},
		{"备份包", "/var/backups/dns-stack", ".tar.zst"},
	} {
		fmt.Fprintf(c.Out, "%s(%s):\n", spec.label, spec.dir)
		entries, err := os.ReadDir(spec.dir)
		if err != nil {
			fmt.Fprintln(c.Out, "  (无)")
			continue
		}
		var names []string
		for _, e := range entries {
			if !e.IsDir() && strings.Contains(e.Name(), spec.suffix) &&
				!strings.HasSuffix(e.Name(), ".sha256") {
				names = append(names, e.Name())
			}
		}
		if len(names) == 0 {
			fmt.Fprintln(c.Out, "  (无)")
			continue
		}
		sort.Sort(sort.Reverse(sort.StringSlice(names)))
		for _, name := range names {
			info, err := os.Stat(filepath.Join(spec.dir, name))
			if err != nil {
				continue
			}
			fmt.Fprintf(c.Out, "  %10d  %s\n", info.Size(), filepath.Join(spec.dir, name))
		}
	}
	return nil
}

func (c *Ctl) MigrationFinish(ctx context.Context) error {
	if !c.Confirm("即将停止本机的 mosproxy/Unbound/面板服务(不删除任何数据)，确认继续？") {
		c.Warnf("已取消")
		return nil
	}
	for _, unit := range []string{
		"mosproxy.service", "unbound.service",
		"dns-stack-panel.service",
	} {
		c.systemctl(ctx, "stop", unit)
	}
	c.systemctl(ctx, "disable", "dns-stack-maintenance.timer")
	c.Okf("旧服务器相关服务已停止(数据仍保留在 /etc/dns-stack /var/lib/dns-stack /var/backups/dns-stack /srv/dns-stack/export)")
	return nil
}

func readSecret(out io.Writer, in io.Reader, prompt string) (string, error) {
	fmt.Fprint(out, prompt)
	if file, ok := in.(*os.File); ok {
		if body, err := readPassword(file); err == nil {
			fmt.Fprintln(out)
			return body, nil
		}
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
