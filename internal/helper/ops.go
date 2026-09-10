package helper

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	cacheTTLMax    = 2592000
	minPasswordLen = 12
	maxPasswordLen = 256
	maxUpdateBytes = 8192
)

var allowedUnits = map[string]bool{
	"mosproxy": true, "unbound": true, "dns-stack-panel": true, "dns-stack-helper": true,
	"dns-stack-sync-rules": true, "dns-stack-collect-polluted": true,
	"dns-stack-renew-cert": true, "dns-stack-backup": true,
	"dns-stack-reference-data": true, "dns-stack-classify": true,
	"dns-stack-verify": true, "dns-stack-publish": true,
	"dns-stack-recursive-routing": true, "dns-stack-chnroute": true, "dns-stack-cn-authority": true,
	"dns-stack-geoip": true, "dns-stack-routing-watchdog": true,
	"dns-stack-ecs-zone": true, "dns-stack-geo-cross": true,
	"wg-quick@wg0": true,
}

var allowedPriorities = map[string]bool{
	"emerg": true, "alert": true, "crit": true, "err": true,
	"warning": true, "notice": true, "info": true, "debug": true,
}

var allowedQTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "MX": true, "TXT": true,
	"NS": true, "SOA": true, "HTTPS": true, "SVCB": true, "PTR": true,
}

var digTargets = map[string][]string{
	"local-unbound": {"@127.0.0.1", "-p", "5335"},
	"foreign-hk":    {"@10.100.0.3", "-p", "5335"},
	"cn-unbound":    {"@10.100.0.2", "-p", "5335"},
}

var DangerousOps = map[string]bool{
	"purge_legacy": true, "clear_audit": true, "vacuum_logs": true,
	"clear_domains": true, "clear_domains_all": true,
	"restart_mosproxy": true, "restart_unbound": true, "rollback_rules": true,
	"import": true, "cert_renew": true, "publish_github": true, "rotate_doh_path": true,
	"set_rule_sources": true, "migration_restore": true,
}

var secretArgKeys = map[string]bool{
	"password": true, "pw": true, "old_password": true,
	"new_password": true, "passwd": true, "token": true,
}

func stringArg(args map[string]any, key string) string {
	switch value := args[key].(type) {
	case string:
		return value
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(value)
	case nil:
		return ""
	default:
		return ""
	}
}

func (h *Helper) scriptPath(parts ...string) string {
	return filepath.ToSlash(filepath.Join(append([]string{h.stackRoot}, parts...)...))
}

func (h *Helper) role() string {
	data, err := os.ReadFile(h.configPath)
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ROLE=") {
			return strings.TrimSpace(strings.SplitN(line, "=", 2)[1])
		}
	}
	return "unknown"
}

func (h *Helper) requireRole(want, what string) result {
	if h.role() != want {
		return failure(what + "只允许在 " + want + " 节点执行")
	}
	return nil
}

func (h *Helper) opReloadMosproxy(map[string]any) result {
	return h.run([]string{"curl", "-fsS", "--max-time", "10", "http://127.0.0.1:8888/ctl/reload"}, 60*time.Second, true)
}

func (h *Helper) opRestartMosproxy(map[string]any) result {
	return h.run([]string{"systemctl", "restart", "mosproxy.service"}, 60*time.Second, true)
}

func (h *Helper) opRestartUnbound(map[string]any) result {
	return h.run([]string{"systemctl", "restart", "unbound.service"}, 60*time.Second, true)
}

func (h *Helper) opPurgeLegacy(map[string]any) result {
	return h.run([]string{h.cli, "--yes", "purge-legacy"}, 60*time.Second, true)
}

func (h *Helper) opSetArchEpoch(map[string]any) result {
	return h.run([]string{h.cli, "set-arch-epoch"}, 60*time.Second, true)
}

func (h *Helper) opVacuumLogs(args map[string]any) result {
	keep := stringArg(args, "keep")
	if keep == "" {
		keep = "7d"
	}
	if !retentionPattern.MatchString(keep) {
		return failure("保留期格式如 7d/2w/1m")
	}
	return h.run([]string{h.cli, "--yes", "vacuum-logs", keep}, 120*time.Second, true)
}

func (h *Helper) opClearAudit(map[string]any) result {
	return h.run([]string{h.cli, "--yes", "clear-audit"}, 60*time.Second, true)
}

func (h *Helper) opClearDomains(args map[string]any) result {
	value := stringArg(args, "days")
	if value == "" {
		value = "7"
	}
	if value != "all" {
		days, err := strconv.Atoi(value)
		if err != nil || days < 1 || days > 3650 {
			return failure("参数需为 1-3650 或 all")
		}
	}
	return h.run([]string{h.cli, "--yes", "clear-domains", value}, 60*time.Second, true)
}

func (h *Helper) opClearDomainsAll(map[string]any) result {
	return h.opClearDomains(map[string]any{"days": "all"})
}

func (h *Helper) opHealthcheck(map[string]any) result {
	return h.run([]string{h.cli, "health"}, 60*time.Second, true)
}

func (h *Helper) opSyncRules(map[string]any) result {
	return h.run([]string{h.scriptPath("scripts", "sync-rules.sh")}, 120*time.Second, true)
}

func (h *Helper) opRollbackRules(map[string]any) result {
	return h.run([]string{h.scriptPath("scripts", "sync-rules.sh"), "--rollback"}, 120*time.Second, true)
}

func (h *Helper) opCollectPollutedIP(map[string]any) result {
	return h.run([]string{h.scriptPath("scripts", "collect-polluted-ip.sh")}, 300*time.Second, false)
}

func (h *Helper) opDoHInfo(map[string]any) result {
	return h.run([]string{h.scriptPath("scripts", "doh-path.sh"), "--print"}, 15*time.Second, false)
}

func (h *Helper) opRotateDoHPath(map[string]any) result {
	return h.run([]string{h.scriptPath("scripts", "doh-path.sh"), "--rotate"}, 60*time.Second, false)
}

func (h *Helper) restorePanelAuthOwnership() {
	h.run([]string{"chown", "dns-stack-panel:dns-stack-panel", h.authPath}, 10*time.Second, true)
	h.run([]string{"chmod", "0400", h.authPath}, 10*time.Second, true)
}

func (h *Helper) opSetPanelPassword(args map[string]any) result {
	password, ok := args["password"].(string)
	if !ok || len([]rune(password)) < minPasswordLen {
		return rejectResult("密码至少 12 位")
	}
	if len([]rune(password)) > maxPasswordLen {
		return rejectResult("密码过长(上限 256 字符)")
	}
	record, err := HashPassword(password)
	if err != nil {
		return failure("生成密码哈希失败: " + err.Error())
	}
	if err := writeAuthRecord(h.authPath, record, false, 0o640); err != nil {
		return failure("写入密码失败: " + err.Error())
	}
	h.restorePanelAuthOwnership()
	h.log("面板访问密码已更新(旧会话已随会话密钥轮换全部失效)")
	return result{"ok": true, "returncode": 0, "stdout": "密码已更新", "stderr": ""}
}

func (h *Helper) opUpdatePanelAuth(args map[string]any) result {
	update, ok := args["update"].(map[string]any)
	if !ok {
		return rejectResult("update 必须是对象")
	}
	encoded, err := json.Marshal(update)
	if err != nil {
		return rejectResult("update 无法序列化")
	}
	if len(encoded) > maxUpdateBytes {
		return rejectResult(errUpdateTooLarge.Error())
	}
	record := MergeAuthUpdate(h.authPath, update)
	if err := writeAuthRecord(h.authPath, record, true, 0o600); err != nil {
		return failure("写入认证配置失败: " + err.Error())
	}
	h.restorePanelAuthOwnership()
	keys := make([]string, 0, len(update))
	for key := range update {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	h.log("面板认证配置已更新: " + strings.Join(keys, ","))
	return result{"ok": true, "returncode": 0, "stdout": "已更新", "stderr": ""}
}

func (h *Helper) opClassifyStart(map[string]any) result {
	return h.run([]string{h.goBin, "classify", "classify"}, 300*time.Second, true)
}

func (h *Helper) opClassifyStop(map[string]any) result {
	return h.run([]string{"systemctl", "stop", "dns-stack-classify.service"}, 60*time.Second, true)
}

func (h *Helper) opClassifyDomain(args map[string]any) result {
	domain, err := SafeDomain(stringArg(args, "domain"))
	if err != nil {
		return errorResult(err.Error())
	}
	return h.run([]string{h.goBin, "classify", "classify", "--domain", domain}, 60*time.Second, true)
}

func (h *Helper) opClassifyAuthority(map[string]any) result {
	if bad := h.requireRole("global-builder", "权威分类"); bad != nil {
		return bad
	}
	return h.run([]string{"flock", "-w", "1700", h.lockPath, h.goBin, "classify", "classify-authority"}, 1800*time.Second, true)
}

func (h *Helper) opBuildRules(map[string]any) result {
	if bad := h.requireRole("global-builder", "规则生成"); bad != nil {
		return bad
	}
	return h.run([]string{"flock", "-w", "1700", h.lockPath, h.goBin, "classify", "build-rules"}, 600*time.Second, true)
}

func (h *Helper) opRebuildRules(map[string]any) result {
	if bad := h.requireRole("global-builder", "规则流水线"); bad != nil {
		return bad
	}
	return h.run([]string{"flock", "-w", "1700", h.lockPath, h.goBin, "classify", "pipeline",
		"--authority-every", "0"}, 2400*time.Second, true)
}

func readable(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
}

func (h *Helper) routingPrerequisiteError() string {
	state := os.Getenv("DNS_STACK_STATE_DIR")
	if state == "" {
		state = "/var/lib/dns-stack"
	}
	candidates := []string{
		os.Getenv("PSL_FILE"),
		state + "/reference/public_suffix_list.dat",
		state + "/psl-data/public_suffix_list.dat",
		"/usr/share/publicsuffix/public_suffix_list.dat",
	}
	geoip := os.Getenv("CNIP_DB")
	if geoip == "" {
		geoip = state + "/geoip/qqwry.ipdb"
	}
	var missing []string
	found := false
	for _, path := range candidates {
		if readable(path) {
			found = true
			break
		}
	}
	if !found {
		missing = append(missing, "Public Suffix List")
	}
	if !readable(geoip) {
		missing = append(missing, "GeoIP 归属库")
	}
	return strings.Join(missing, "、")
}

func (h *Helper) opRefreshRouting(map[string]any) result {
	if bad := h.requireRole("cn-resolver", "分流数据刷新"); bad != nil {
		return bad
	}
	if missing := h.routingPrerequisiteError(); missing != "" {
		return failure("缺少 " + missing + "，未改动分流产物")
	}
	return h.runSteps([]step{
		{"direct4", []string{h.scriptPath("scripts", "update-chnroute.sh")}, 900 * time.Second},
		{"cn-authority", []string{h.scriptPath("scripts", "update-cn-authority.sh")}, 300 * time.Second},
		{"ecs-zone", []string{h.goBin, "ecs-zone"}, 900 * time.Second},
	})
}

func (h *Helper) opPullCandidates(map[string]any) result {
	return h.run([]string{h.goBin, "classify", "pull"}, 120*time.Second, true)
}

func (h *Helper) opPublishGitHub(map[string]any) result {
	return h.run([]string{h.goBin, "classify", "publish"}, 120*time.Second, true)
}

func (h *Helper) opUpdateReferenceData(map[string]any) result {
	return h.run([]string{h.goBin, "classify", "update-reference-data"}, 120*time.Second, true)
}

func (h *Helper) opBackup(args map[string]any) result {
	command := []string{h.scriptPath("scripts", "backup.sh")}
	if truthy(args["include_secrets"]) {
		command = append(command, "--include-secrets")
	}
	return h.run(command, 300*time.Second, true)
}

func (h *Helper) opExport(args map[string]any) result {
	mode := stringArg(args, "mode")
	if mode == "" {
		mode = "config"
	}
	if mode != "config" && mode != "state" && mode != "full" {
		return errorResult("非法的导出模式")
	}
	return h.run([]string{h.scriptPath("migration", "export.sh"), "--mode", mode}, 300*time.Second, true)
}

func (h *Helper) opImport(args map[string]any) result {
	resolved, err := filepath.EvalSymlinks(stringArg(args, "path"))
	if err != nil {
		return errorResult("文件不存在")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || !strings.HasPrefix(filepath.ToSlash(resolved), "/srv/dns-stack/export/") {
		return errorResult("导入文件必须位于 /srv/dns-stack/export/ 下")
	}
	return h.run([]string{h.scriptPath("migration", "import.sh"), resolved}, 600*time.Second, true)
}

func (h *Helper) migrationInbox() string {
	return filepath.ToSlash(filepath.Join(h.stateDir, "migration-inbox")) + "/"
}

func (h *Helper) opMigrationRestore(args map[string]any) result {
	raw := stringArg(args, "path")
	if raw == "" {
		return rejectResult("必须指定迁移包路径")
	}
	resolved, err := filepath.EvalSymlinks(raw)
	if err != nil {
		return errorResult("迁移包不存在")
	}
	info, err := os.Stat(resolved)
	inbox := h.migrationInbox()
	if err != nil || !info.Mode().IsRegular() ||
		!strings.HasPrefix(filepath.ToSlash(resolved), inbox) {
		return errorResult("迁移包必须位于 " + inbox + " 下")
	}
	if info.Size() > 64<<20 {
		return errorResult("迁移包超过 64MB 上限")
	}
	cmd := []string{h.goBin, "migration-restore", "--bundle", resolved, "--json"}
	if stringArg(args, "dry_run") == "true" {
		cmd = append(cmd, "--dry-run")
	}
	return h.run(cmd, 300*time.Second, true)
}

func (h *Helper) opCertCheck(map[string]any) result {
	return h.run([]string{h.scriptPath("scripts", "renew-cert.sh"), "--check-only"}, 60*time.Second, false)
}

func (h *Helper) opCertRenew(map[string]any) result {
	return h.run([]string{h.scriptPath("scripts", "renew-cert.sh")}, 180*time.Second, false)
}

func (h *Helper) opCertInfo(map[string]any) result {
	cert := "/etc/dns-stack/secrets/doh-dot.pem"
	if _, err := os.Stat(cert); err != nil {
		return result{"ok": false, "returncode": 1, "stdout": "", "stderr": "证书文件不存在"}
	}
	return h.run([]string{"openssl", "x509", "-in", cert, "-noout",
		"-enddate", "-startdate", "-issuer", "-ext", "subjectAltName"}, 15*time.Second, false)
}

func (h *Helper) opListBackups(map[string]any) result {
	out := map[string][]map[string]any{"backups": {}, "exports": {}}
	sources := []struct {
		key       string
		directory string
		suffixes  []string
	}{
		{"backups", "/var/backups/dns-stack", []string{".tar.zst", ".tar.zst.age"}},
		{"exports", "/srv/dns-stack/export", []string{".tar.zst.age"}},
	}
	for _, source := range sources {
		entries, err := os.ReadDir(source.directory)
		if err == nil {
			for _, entry := range entries {
				matched := false
				for _, suffix := range source.suffixes {
					if strings.HasSuffix(entry.Name(), suffix) {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
				info, err := entry.Info()
				if err != nil || !info.Mode().IsRegular() {
					continue
				}
				out[source.key] = append(out[source.key], map[string]any{
					"name": entry.Name(), "size": info.Size(), "mtime": info.ModTime().Unix(),
				})
			}
		}
		items := out[source.key]
		sort.SliceStable(items, func(i, j int) bool {
			return items[i]["mtime"].(int64) > items[j]["mtime"].(int64)
		})
		if len(items) > 20 {
			items = items[:20]
		}
		out[source.key] = items
	}
	encoded, _ := json.Marshal(out)
	return result{"ok": true, "returncode": 0, "stdout": string(encoded), "stderr": ""}
}

func (h *Helper) opLogs(args map[string]any) result {
	unit := stringArg(args, "unit")
	if !allowedUnits[unit] {
		return errorResult("不允许查看该服务日志: " + unit)
	}
	lines := 200
	if raw, ok := args["lines"].(float64); ok {
		lines = int(raw)
	}
	if lines < 1 {
		lines = 1
	}
	if lines > 2000 {
		lines = 2000
	}
	command := []string{"journalctl", "-u", unit + ".service", "-n", strconv.Itoa(lines),
		"--no-pager", "--output", "short-iso"}
	if priority := stringArg(args, "priority"); priority != "" {
		if !allowedPriorities[priority] {
			return errorResult("非法的日志等级")
		}
		command = append(command, "-p", priority)
	}
	if since := stringArg(args, "since"); since != "" {
		if !sincePattern.MatchString(since) {
			return errorResult("非法的时间范围")
		}
		command = append(command, "--since", since)
	}
	return h.run(command, 30*time.Second, true)
}

func readYAMLInt(path, key string) any {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, key+":") {
			continue
		}
		value := strings.TrimSpace(strings.SplitN(strings.SplitN(trimmed, ":", 2)[1], "#", 2)[0])
		number, err := strconv.Atoi(value)
		if err != nil {
			return nil
		}
		return number
	}
	return nil
}

func (h *Helper) opCacheInfo(map[string]any) result {
	unbound := map[string]any{}
	for _, option := range []string{"serve-expired-ttl", "serve-expired-client-timeout", "cache-max-ttl"} {
		r := h.run([]string{"unbound-control", "-c", "/etc/unbound/unbound.conf", "get_option", option}, 10*time.Second, false)
		if code, _ := r["returncode"].(int); code != 0 {
			continue
		}
		text := strings.TrimSpace(r["stdout"].(string))
		if number, err := strconv.Atoi(text); err == nil {
			unbound[option] = number
		} else {
			unbound[option] = text
		}
	}
	info := map[string]any{
		"mosproxy": map[string]any{
			"optimistic_ttl": readYAMLInt(h.mosproxyConf, "optimistic_ttl"),
			"maximum_ttl":    readYAMLInt(h.mosproxyConf, "maximum_ttl"),
		},
		"unbound": unbound,
	}
	encoded, _ := json.Marshal(info)
	return result{"ok": true, "returncode": 0, "stdout": string(encoded), "stderr": ""}
}

func replaceIntField(path, key string, value int) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	pattern := regexp.MustCompile(`(?m)^(\s*` + regexp.QuoteMeta(key) + `:\s*)\d+`)
	if !pattern.Match(data) {
		return false, nil
	}
	updated := pattern.ReplaceAll(data, []byte("${1}"+strconv.Itoa(value)))
	info, err := os.Stat(path)
	mode := os.FileMode(0o644)
	if err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.WriteFile(path, updated, mode); err != nil {
		return false, err
	}
	return true, nil
}

func (h *Helper) opSetCacheTTL(args map[string]any) result {
	raw, ok := args["ttl"].(float64)
	if !ok {
		if text := stringArg(args, "ttl"); text != "" {
			parsed, err := strconv.Atoi(text)
			if err != nil {
				return result{"ok": false, "returncode": 1, "stdout": "", "stderr": "ttl 必须是整数(秒)"}
			}
			raw = float64(parsed)
		} else {
			return result{"ok": false, "returncode": 1, "stdout": "", "stderr": "ttl 必须是整数(秒)"}
		}
	}
	ttl := int(raw)
	if ttl < 0 || ttl > cacheTTLMax {
		return result{"ok": false, "returncode": 1, "stdout": "",
			"stderr": "ttl 超出允许范围 0~" + strconv.Itoa(cacheTTLMax) + " 秒"}
	}

	r := h.run([]string{"unbound-control", "-c", "/etc/unbound/unbound.conf",
		"set_option", "serve-expired-ttl:", strconv.Itoa(ttl)}, 15*time.Second, false)
	if code, _ := r["returncode"].(int); code != 0 {
		stderr, _ := r["stderr"].(string)
		return result{"ok": false, "returncode": 1, "stdout": "", "stderr": "Unbound 设置失败: " + stderr}
	}
	lines := []string{"Unbound serve-expired-ttl 已即时生效: " + strconv.Itoa(ttl)}

	if changed, err := replaceIntField(h.unboundConf, "serve-expired-ttl", ttl); err != nil {
		lines = append(lines, "警告: Unbound 配置文件未能同步("+err.Error()+")，重启后会恢复旧值")
	} else if changed {
		lines = append(lines, "Unbound 配置文件已同步")
	}

	if changed, err := replaceIntField(h.mosproxyConf, "optimistic_ttl", ttl); err != nil {
		lines = append(lines, "警告: mosproxy 配置写入失败("+err.Error()+")")
	} else if !changed {
		lines = append(lines, "警告: mosproxy 配置里没找到 optimistic_ttl，未改动")
	} else {
		lines = append(lines, "mosproxy optimistic_ttl 已写入: "+strconv.Itoa(ttl)+"(需重启 mosproxy 后生效)")
	}

	h.log("调整乐观缓存 TTL: " + strconv.Itoa(ttl))
	return result{"ok": true, "returncode": 0, "stdout": strings.Join(lines, "\n"), "stderr": ""}
}

func (h *Helper) opSetRuleSources(args map[string]any) result {
	rawBase, _ := args["github_raw_base"].(string)
	if rawBase == "" {
		return result{"ok": false, "returncode": 1, "stdout": "", "stderr": "github_raw_base 不能为空"}
	}
	if message := validateRuleURL(rawBase, "github_raw_base"); message != "" {
		return result{"ok": false, "returncode": 1, "stdout": "", "stderr": message}
	}
	mirror1, _ := args["github_mirror_1"].(string)
	if message := validateRuleURL(mirror1, "github_mirror_1"); message != "" {
		return result{"ok": false, "returncode": 1, "stdout": "", "stderr": message}
	}
	mirror2, _ := args["github_mirror_2"].(string)
	if message := validateRuleURL(mirror2, "github_mirror_2"); message != "" {
		return result{"ok": false, "returncode": 1, "stdout": "", "stderr": message}
	}
	repository, _ := args["github_repository"].(string)
	if !repositoryPattern.MatchString(repository) {
		return result{"ok": false, "returncode": 1, "stdout": "", "stderr": "github_repository 必须是 owner/repo 形式"}
	}
	branch, _ := args["github_branch"].(string)
	if branch == "" {
		return result{"ok": false, "returncode": 1, "stdout": "", "stderr": "github_branch 不能为空"}
	}
	if !branchPattern.MatchString(branch) {
		return result{"ok": false, "returncode": 1, "stdout": "", "stderr": "github_branch 含非法字符或过长(≤80)"}
	}

	updates := [][2]string{
		{"GITHUB_RAW_BASE", rawBase},
		{"GITHUB_MIRROR_1", mirror1},
		{"GITHUB_MIRROR_2", mirror2},
		{"GITHUB_REPOSITORY", repository},
		{"GITHUB_BRANCH", branch},
	}
	data, err := os.ReadFile(h.configPath)
	if err != nil {
		return result{"ok": false, "returncode": 1, "stdout": "", "stderr": "读取配置失败: " + err.Error()}
	}
	text := string(data)
	var appended []string
	for _, pair := range updates {
		pattern := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(pair[0]) + `=.*$`)
		if pattern.MatchString(text) {
			text = pattern.ReplaceAllLiteralString(text, pair[0]+"="+pair[1])
			continue
		}
		appended = append(appended, pair[0]+"="+pair[1])
	}
	if len(appended) > 0 {
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		text += strings.Join(appended, "\n") + "\n"
	}
	mode := os.FileMode(0o600)
	if info, err := os.Stat(h.configPath); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.WriteFile(h.configPath, []byte(text), mode); err != nil {
		return result{"ok": false, "returncode": 1, "stdout": "", "stderr": "写入配置失败: " + err.Error()}
	}
	h.log("GitHub 规则源已更新: raw_base=" + rawBase + " repository=" + repository + " branch=" + branch)
	return result{"ok": true, "returncode": 0, "stdout": "规则源已更新，下次 sync-rules 运行时生效", "stderr": ""}
}

func (h *Helper) opUnboundStats(map[string]any) result {
	return h.run([]string{"unbound-control", "-c", "/etc/unbound/unbound.conf", "stats_noreset"}, 15*time.Second, false)
}

func (h *Helper) opServiceStatus(args map[string]any) result {
	unit := stringArg(args, "unit")
	if !allowedUnits[unit] {
		return errorResult("不允许查询该服务: " + unit)
	}
	return h.run([]string{"systemctl", "show", unit + ".service", unit + ".timer",
		"--property=Id,LoadState,ActiveState,SubState,Result,ExecMainStatus," +
			"ExecMainStartTimestamp,ExecMainExitTimestamp,MemoryCurrent,NRestarts," +
			"NextElapseUSecRealtime,LastTriggerUSec",
		"--no-pager"}, 15*time.Second, true)
}

func (h *Helper) opDNSTest(args map[string]any) result {
	domain, err := SafeDomain(stringArg(args, "domain"))
	if err != nil {
		return errorResult(err.Error())
	}
	qtype := strings.ToUpper(stringArg(args, "qtype"))
	if qtype == "" {
		qtype = "A"
	}
	if !allowedQTypes[qtype] {
		return errorResult("不支持的查询类型")
	}
	server := stringArg(args, "server")
	if server == "" {
		server = "local-unbound"
	}
	target, ok := digTargets[server]
	if !ok {
		return errorResult("不支持的测试目标")
	}
	command := []string{"dig"}
	command = append(command, target...)
	command = append(command, domain, qtype, "+time=5", "+tries=1", "+stats")
	if raw := strings.TrimSpace(stringArg(args, "subnet")); raw != "" {
		subnet, ok := SafeClientSubnet(raw)
		if !ok {
			return errorResult("subnet 必须是规范的全局 IPv4 /24 网段")
		}
		command = append(command, "+subnet="+subnet)
	}
	return h.run(command, 20*time.Second, false)
}

func (h *Helper) opMosproxyMetrics(map[string]any) result {
	return h.run([]string{"curl", "-fsS", "--max-time", "5", "http://127.0.0.1:8888/metrics"}, 10*time.Second, false)
}

func (h *Helper) opNetworkExits(args map[string]any) result {
	tunnel := stringArg(args, "interface")
	if tunnel == "" {
		tunnel = "wg0"
	}
	if !interfacePattern.MatchString(tunnel) {
		return rejectResult("非法网络接口名")
	}
	out := result{"returncode": 0, "interfaces": map[string]any{},
		"tunnel_peer": nil, "public_ipv4": nil, "default_interface": nil}
	interfaces := out["interfaces"].(map[string]any)

	if r := h.run([]string{"ip", "-4", "-o", "addr", "show"}, 10*time.Second, false); truthy(r["ok"]) {
		for _, line := range strings.Split(r["stdout"].(string), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 4 && fields[2] == "inet" {
				if _, seen := interfaces[fields[1]]; !seen {
					interfaces[fields[1]] = strings.SplitN(fields[3], "/", 2)[0]
				}
			}
		}
	}

	if r := h.run([]string{"ip", "-4", "route", "show", "default"}, 10*time.Second, false); truthy(r["ok"]) {
		fields := strings.Fields(r["stdout"].(string))
		for i, field := range fields {
			if field == "dev" && i+1 < len(fields) {
				out["default_interface"] = fields[i+1]
				break
			}
		}
	}

	defaultRoutePeer := ""
	if r := h.run([]string{"wg", "show", tunnel, "allowed-ips"}, 10*time.Second, false); truthy(r["ok"]) {
		for _, line := range strings.Split(r["stdout"].(string), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			for _, allowed := range fields[1:] {
				if allowed == "0.0.0.0/0" {
					defaultRoutePeer = fields[0]
					break
				}
			}
			if defaultRoutePeer != "" {
				break
			}
		}
	}

	if r := h.run([]string{"wg", "show", tunnel, "endpoints"}, 10*time.Second, false); truthy(r["ok"]) {
		fallback, matched := "", false
		for _, line := range strings.Split(r["stdout"].(string), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 || !strings.Contains(fields[1], ":") {
				continue
			}
			address := fields[1][:strings.LastIndex(fields[1], ":")]
			if defaultRoutePeer != "" && fields[0] == defaultRoutePeer {
				out["tunnel_peer"] = address
				matched = true
				break
			}
			if fallback == "" {
				fallback = address
			}
		}
		if !matched {
			if defaultRoutePeer == "" {
				if fallback != "" {
					out["tunnel_peer"] = fallback
				}
				out["tunnel_peer_note"] = nil
			} else {
				out["tunnel_peer"] = nil
				out["tunnel_peer_note"] = "承载 0.0.0.0/0 的 peer 没有已知 endpoint，隧道可能未建立"
			}
		}
	}

	if data, err := os.ReadFile(h.configPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PUBLIC_IPV4=") {
				if value := strings.TrimSpace(strings.SplitN(line, "=", 2)[1]); value != "" {
					out["public_ipv4"] = value
				}
				break
			}
		}
	}
	return out
}

const rejectionKey = "__rejected__"

func errorResult(message string) result {
	return result{"ok": false, "stderr": message}
}

func rejectResult(message string) result {
	return result{rejectionKey: message}
}

func (h *Helper) operations() map[string]func(map[string]any) result {
	return map[string]func(map[string]any) result{
		"network_exits":         h.opNetworkExits,
		"reload_mosproxy":       h.opReloadMosproxy,
		"restart_mosproxy":      h.opRestartMosproxy,
		"restart_unbound":       h.opRestartUnbound,
		"healthcheck":           h.opHealthcheck,
		"sync_rules":            h.opSyncRules,
		"rollback_rules":        h.opRollbackRules,
		"collect_polluted_ip":   h.opCollectPollutedIP,
		"doh_info":              h.opDoHInfo,
		"rotate_doh_path":       h.opRotateDoHPath,
		"set_panel_password":    h.opSetPanelPassword,
		"update_panel_auth":     h.opUpdatePanelAuth,
		"classify_start":        h.opClassifyStart,
		"classify_stop":         h.opClassifyStop,
		"classify_domain":       h.opClassifyDomain,
		"classify_authority":    h.opClassifyAuthority,
		"build_rules":           h.opBuildRules,
		"rebuild_rules":         h.opRebuildRules,
		"refresh_routing":       h.opRefreshRouting,
		"pull_candidates":       h.opPullCandidates,
		"publish_github":        h.opPublishGitHub,
		"update_reference_data": h.opUpdateReferenceData,
		"backup":                h.opBackup,
		"purge_legacy":          h.opPurgeLegacy,
		"clear_audit":           h.opClearAudit,
		"vacuum_logs":           h.opVacuumLogs,
		"clear_domains":         h.opClearDomains,
		"clear_domains_all":     h.opClearDomainsAll,
		"set_arch_epoch":        h.opSetArchEpoch,
		"export":                h.opExport,
		"import":                h.opImport,
		"migration_restore":     h.opMigrationRestore,
		"cert_check":            h.opCertCheck,
		"cert_info":             h.opCertInfo,
		"cert_renew":            h.opCertRenew,
		"list_backups":          h.opListBackups,
		"logs":                  h.opLogs,
		"unbound_stats":         h.opUnboundStats,
		"cache_info":            h.opCacheInfo,
		"set_cache_ttl":         h.opSetCacheTTL,
		"set_rule_sources":      h.opSetRuleSources,
		"service_status":        h.opServiceStatus,
		"dns_test":              h.opDNSTest,
		"mosproxy_metrics":      h.opMosproxyMetrics,
	}
}
