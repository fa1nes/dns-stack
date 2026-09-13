package rulesync

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/cidrutil"
)

const (
	FileCN       = "cn.txt"
	FileGFW      = "gfw.txt"
	FileCNCIDR   = "cn-ip-cidr.txt"
	FilePolluted = "polluted-ip-cidr.txt"

	shrinkFloorRatio = 80
	shrinkMinRows    = 20
)

var BundleFiles = []string{FileCN, FileGFW, FileCNCIDR, FilePolluted}

var generatedAtRe = regexp.MustCompile(`^#\s*generated-at:\s*([0-9]+)`)

type Options struct {
	StateDir string
	Sources  []string
	Force    bool

	HistoryKeep int
	Now         func() time.Time
	Fetch       func(ctx context.Context, url string) ([]byte, error)
	Reload      func(ctx context.Context) error
	Health      func(ctx context.Context) error
	Log         func(format string, args ...any)
}

type Result struct {
	Applied     bool
	GeneratedAt int64
	Source      string
	Reason      string
	Counts      map[string]int
}

type bundle struct {
	source      string
	generatedAt int64
	clean       map[string][]byte
	remoteBody  []byte
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o Options) logf(format string, args ...any) {
	if o.Log != nil {
		o.Log(format, args...)
	}
}

func (o Options) syncDir() string  { return filepath.Join(o.StateDir, "sync-state") }
func (o Options) histDir() string  { return filepath.Join(o.StateDir, "rule-history") }
func (o Options) localIPs() string { return filepath.Join(o.StateDir, "polluted-ip.txt") }

func (o Options) remoteSnapshot() string {
	return filepath.Join(o.syncDir(), "polluted-ip-cidr.remote.txt")
}

func (o Options) localCIDRs() string {
	return filepath.Join(o.syncDir(), "polluted-ip-cidr.local.txt")
}

func (o Options) lastGenPath() string {
	return filepath.Join(o.syncDir(), "last-generated-at")
}

func (o Options) holdPath() string {
	return filepath.Join(o.syncDir(), "rollback-hold-generated-at")
}

func Sync(ctx context.Context, opt Options) (Result, error) {
	if opt.StateDir == "" {
		return Result{}, fmt.Errorf("状态目录未配置")
	}
	if opt.Fetch == nil {
		return Result{}, fmt.Errorf("未提供下载器")
	}
	if len(opt.Sources) == 0 {
		return Result{}, fmt.Errorf("没有配置任何规则源")
	}
	for _, dir := range []string{opt.syncDir(), opt.histDir()} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return Result{}, err
		}
	}

	var best *bundle
	for _, src := range opt.Sources {
		src = strings.TrimRight(strings.TrimSpace(src), "/")
		if src == "" {
			continue
		}
		b, err := fetchBundle(ctx, opt, src)
		if err != nil {
			opt.logf("规则源不可用 %s: %v", src, err)
			continue
		}
		opt.logf("候选规则包 %s (版本 %d)", src, b.generatedAt)
		if best == nil || b.generatedAt > best.generatedAt {
			best = b
		}
	}
	if best == nil {
		opt.appendHistory("bundle_download_failed")
		return Result{Reason: "所有规则源均不可用，保留当前规则不变"}, nil
	}

	prev := readInt64(opt.lastGenPath())
	hold := readInt64(opt.holdPath())
	if !opt.Force && hold > 0 && best.generatedAt <= hold {
		return Result{Reason: fmt.Sprintf("处于回滚保持状态，远端版本 %d 未高于 %d", best.generatedAt, hold)}, nil
	}
	if best.generatedAt < prev {
		opt.appendHistory(fmt.Sprintf("stale_skipped remote=%d local=%d", best.generatedAt, prev))
		return Result{Reason: fmt.Sprintf("远端版本 %d 旧于本机 %d", best.generatedAt, prev)}, nil
	}

	best.remoteBody = best.clean[FilePolluted]
	merged, err := mergePolluted(best.remoteBody, opt.localIPs(), opt.localCIDRs())
	if err != nil {
		return Result{}, fmt.Errorf("合并本地污染集合失败: %w", err)
	}
	best.clean[FilePolluted] = merged
	if err := disjoint(best.clean[FileCNCIDR], best.clean[FilePolluted]); err != nil {
		return Result{}, err
	}

	if !opt.Force && best.generatedAt == prev && prev > 0 {
		if old, err := os.ReadFile(opt.remoteSnapshot()); err == nil && len(old) > 0 &&
			!bytes.Equal(old, best.remoteBody) {
			opt.appendHistory(fmt.Sprintf("same_version_polluted_conflict gen=%d", prev))
			return Result{Reason: fmt.Sprintf("远端污染快照与本机版本号相同(%d)但内容不同，拒绝覆盖", prev)}, nil
		}
	}

	unchanged := true
	for _, name := range BundleFiles {
		old, err := os.ReadFile(filepath.Join(opt.StateDir, name))
		if err != nil || !bytes.Equal(old, best.clean[name]) {
			unchanged = false
			break
		}
	}
	if unchanged {
		if err := writeAtomic(opt.remoteSnapshot(), best.remoteBody); err != nil {
			return Result{}, err
		}
		opt.recordVersion(best.generatedAt)
		return Result{GeneratedAt: best.generatedAt, Source: best.source, Reason: "内容无变化，不重载"}, nil
	}
	if !opt.Force && best.generatedAt == prev && prev > 0 {
		opt.appendHistory(fmt.Sprintf("same_version_conflict gen=%d", prev))
		return Result{Reason: fmt.Sprintf("远端规则与本机版本号相同(%d)但内容不同，拒绝覆盖", prev)}, nil
	}

	if !opt.Force {
		if reason := opt.shrinkGuard(best); reason != "" {
			return Result{Reason: reason}, nil
		}
	}

	backup, err := opt.backup()
	if err != nil {
		return Result{}, err
	}
	if err := opt.install(ctx, best); err != nil {
		if rerr := opt.restore(ctx, backup); rerr != nil {
			opt.logf("回滚后重载失败，请立即检查服务: %v", rerr)
		}
		os.RemoveAll(backup)
		return Result{}, err
	}
	opt.keepHistory(backup)
	opt.recordVersion(best.generatedAt)
	os.Remove(opt.holdPath())
	opt.appendHistory(fmt.Sprintf("bundle_ok gen=%d", best.generatedAt))

	counts := make(map[string]int, len(BundleFiles))
	for _, name := range BundleFiles {
		counts[name] = countRows(best.clean[name])
	}
	return Result{Applied: true, GeneratedAt: best.generatedAt, Source: best.source, Counts: counts}, nil
}

func fetchBundle(ctx context.Context, opt Options, src string) (*bundle, error) {
	b := &bundle{source: src, clean: make(map[string][]byte, len(BundleFiles))}
	for _, name := range BundleFiles {
		body, err := opt.Fetch(ctx, src+"/"+name)
		if err != nil {
			return nil, fmt.Errorf("%s 下载失败: %w", name, err)
		}
		gen, ok := parseGeneratedAt(body)
		if !ok {
			return nil, fmt.Errorf("%s 缺少 generated-at 头", name)
		}
		if b.generatedAt == 0 {
			b.generatedAt = gen
		} else if b.generatedAt != gen {
			return nil, fmt.Errorf("四文件版本不一致: %d vs %d", b.generatedAt, gen)
		}
		switch name {
		case FileCN, FileGFW:
			cleaned, err := cleanDomains(body)
			if err != nil {
				return nil, fmt.Errorf("%s 域名校验失败: %w", name, err)
			}
			b.clean[name] = cleaned
		default:
			cleaned, err := cleanCIDRs(body)
			if err != nil {
				return nil, fmt.Errorf("%s CIDR 校验失败: %w", name, err)
			}
			b.clean[name] = cleaned
		}
	}
	if err := disjoint(b.clean[FileCNCIDR], b.clean[FilePolluted]); err != nil {
		return nil, err
	}
	if err := CheckRuleSets(rows(b.clean[FileCN]), rows(b.clean[FileGFW])); err != nil {
		return nil, err
	}
	return b, nil
}

func (o Options) shrinkGuard(b *bundle) string {
	for _, name := range BundleFiles {
		old, err := os.ReadFile(filepath.Join(o.StateDir, name))
		if err != nil {
			continue
		}
		oc := countRows(old)
		if oc == 0 {
			continue
		}
		nc := countRows(b.clean[name])
		if nc == 0 {
			return fmt.Sprintf("%s 从 %d 条降为空集，保留旧规则待人工确认（确认无误用 --force）", name, oc)
		}
		if oc > shrinkMinRows && nc < oc*shrinkFloorRatio/100 {
			return fmt.Sprintf("%s 从 %d 骤降到 %d，保留旧规则待人工确认（确认无误用 --force）", name, oc, nc)
		}
	}
	return ""
}

func (o Options) backup() (string, error) {
	dir, err := os.MkdirTemp(o.histDir(), ".attempt-"+o.now().Format("20060102150405")+"-*")
	if err != nil {
		return "", err
	}
	for _, name := range BundleFiles {
		if err := copyOrMark(filepath.Join(o.StateDir, name), filepath.Join(dir, name)); err != nil {
			return "", err
		}
	}
	for _, item := range [][2]string{
		{o.remoteSnapshot(), "polluted-ip-cidr.remote.txt"},
		{o.localCIDRs(), "polluted-ip-cidr.local.txt"},
		{o.localIPs(), "polluted-ip.local.txt"},
		{o.lastGenPath(), "generated-at"},
	} {
		if err := copyOrMark(item[0], filepath.Join(dir, item[1])); err != nil {
			return "", err
		}
	}
	return dir, nil
}

func (o Options) install(ctx context.Context, b *bundle) error {
	staged := make([]string, 0, len(BundleFiles)+1)
	defer func() {
		for _, p := range staged {
			os.Remove(p)
		}
	}()
	for _, name := range BundleFiles {
		temp := filepath.Join(o.StateDir, "."+name+".new")
		if err := os.WriteFile(temp, b.clean[name], 0o644); err != nil {
			return err
		}
		staged = append(staged, temp)
	}
	snapTemp := o.remoteSnapshot() + ".new"
	if err := os.WriteFile(snapTemp, b.remoteBody, 0o644); err != nil {
		return err
	}
	staged = append(staged, snapTemp)

	for _, name := range BundleFiles {
		if err := os.Rename(filepath.Join(o.StateDir, "."+name+".new"), filepath.Join(o.StateDir, name)); err != nil {
			return err
		}
	}
	if err := os.Rename(snapTemp, o.remoteSnapshot()); err != nil {
		return err
	}
	staged = nil

	if o.Reload != nil {
		if err := o.Reload(ctx); err != nil {
			return fmt.Errorf("重载失败: %w", err)
		}
	}
	if o.Health != nil {
		if err := o.Health(ctx); err != nil {
			return fmt.Errorf("重载后健康检查失败: %w", err)
		}
	}
	return nil
}

func (o Options) restore(ctx context.Context, dir string) error {
	for _, name := range BundleFiles {
		restoreOrRemove(filepath.Join(dir, name), filepath.Join(o.StateDir, name))
	}
	restoreOrRemove(filepath.Join(dir, "polluted-ip-cidr.remote.txt"), o.remoteSnapshot())
	restoreOrRemove(filepath.Join(dir, "polluted-ip-cidr.local.txt"), o.localCIDRs())
	restoreOrRemove(filepath.Join(dir, "polluted-ip.local.txt"), o.localIPs())
	if o.Reload == nil {
		return nil
	}
	return o.Reload(ctx)
}

func (o Options) keepHistory(backup string) {
	if o.HistoryKeep <= 0 {
		os.RemoveAll(backup)
		return
	}
	name := strings.TrimPrefix(filepath.Base(backup), ".attempt-")
	if err := os.Rename(backup, filepath.Join(o.histDir(), "bundle-"+name)); err != nil {
		os.RemoveAll(backup)
		return
	}
	entries, err := os.ReadDir(o.histDir())
	if err != nil {
		return
	}
	var kept []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "bundle-") {
			kept = append(kept, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(kept)))
	for _, old := range kept[min(len(kept), o.HistoryKeep):] {
		os.RemoveAll(filepath.Join(o.histDir(), old))
	}
}

func (o Options) recordVersion(gen int64) {
	writeAtomic(o.lastGenPath(), []byte(strconv.FormatInt(gen, 10)+"\n"))
}

func (o Options) appendHistory(line string) {
	f, err := os.OpenFile(filepath.Join(o.syncDir(), "history.log"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", o.now().UTC().Format(time.RFC3339), line)
}

func Rollback(ctx context.Context, opt Options) error {
	entries, err := os.ReadDir(opt.histDir())
	if err != nil {
		return fmt.Errorf("没有可回滚的历史规则包")
	}
	var latest string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "bundle-") && e.Name() > latest {
			latest = e.Name()
		}
	}
	if latest == "" {
		return fmt.Errorf("没有可回滚的历史规则包")
	}
	target := filepath.Join(opt.histDir(), latest)
	current := readInt64(opt.lastGenPath())

	before, err := opt.backup()
	if err != nil {
		return err
	}
	defer os.RemoveAll(before)
	if err := opt.restore(ctx, target); err != nil {
		if rerr := opt.restore(ctx, before); rerr != nil {
			opt.logf("恢复操作前规则后重载仍失败，请立即检查服务: %v", rerr)
		}
		return fmt.Errorf("回滚后的重载失败，已恢复操作前规则文件: %w", err)
	}
	if gen, err := os.ReadFile(filepath.Join(target, "generated-at")); err == nil {
		writeAtomic(opt.lastGenPath(), gen)
	} else {
		writeAtomic(opt.lastGenPath(), []byte("0\n"))
	}
	writeAtomic(opt.holdPath(), []byte(strconv.FormatInt(current, 10)+"\n"))
	opt.logf("已回滚规则包: %s", latest)
	opt.logf("自动同步将等待 generated-at 高于 %d 的新版本", current)
	return nil
}

func cleanDomains(body []byte) ([]byte, error) {
	seen := make(map[string]struct{})
	var names []string
	for _, line := range rows(body) {
		name := strings.TrimSuffix(strings.ToLower(line), ".")
		if name == "" {
			continue
		}
		if !ValidDomain(name) {
			return nil, fmt.Errorf("非法域名: %s", name)
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, nil
	}
	return []byte(strings.Join(names, "\n") + "\n"), nil
}

func cleanCIDRs(body []byte) ([]byte, error) {
	var prefixes []netip.Prefix
	for _, line := range rows(body) {
		p, err := cidrutil.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("非法 CIDR %q: %w", line, err)
		}
		prefixes = append(prefixes, p)
	}
	return []byte(cidrutil.Render(cidrutil.CollapsePrefixes(prefixes))), nil
}

func mergePolluted(remote []byte, localIPsPath, localCIDRsPath string) ([]byte, error) {
	var prefixes []netip.Prefix
	parsed, err := cidrutil.ReadPrefixes(bytes.NewReader(remote))
	if err != nil {
		return nil, err
	}
	prefixes = append(prefixes, parsed...)
	if items, err := cidrutil.ReadPrefixFile(localCIDRsPath); err == nil {
		prefixes = append(prefixes, items...)
	}
	if body, err := os.ReadFile(localIPsPath); err == nil {
		for _, line := range rows(body) {
			addr, err := netip.ParseAddr(line)
			if err != nil {
				continue
			}
			addr = addr.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return []byte(cidrutil.Render(cidrutil.CollapsePrefixes(prefixes))), nil
}

func disjoint(cnBody, pollutedBody []byte) error {
	cn, err := cidrutil.ReadPrefixes(bytes.NewReader(cnBody))
	if err != nil {
		return err
	}
	polluted, err := cidrutil.ReadPrefixes(bytes.NewReader(pollutedBody))
	if err != nil {
		return err
	}
	if left, right, overlap := cidrutil.FirstOverlap(cn, polluted); overlap {
		return fmt.Errorf("CN CIDR 与污染 CIDR 存在重叠: %s <-> %s", left, right)
	}
	return nil
}

func parseGeneratedAt(body []byte) (int64, bool) {
	for _, line := range strings.Split(string(body), "\n") {
		if m := generatedAtRe.FindStringSubmatch(strings.TrimRight(line, "\r")); m != nil {
			v, err := strconv.ParseInt(m[1], 10, 64)
			return v, err == nil && v > 0
		}
	}
	return 0, false
}

func rows(body []byte) []string {
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func countRows(body []byte) int { return len(rows(body)) }

func readInt64(path string) int64 {
	body, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(body)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func writeAtomic(path string, body []byte) error {
	temp := path + ".new"
	if err := os.WriteFile(temp, body, 0o644); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		os.Remove(temp)
		return err
	}
	return nil
}

func copyOrMark(src, dst string) error {
	body, err := os.ReadFile(src)
	if err != nil {
		return os.WriteFile(dst+".missing", nil, 0o644)
	}
	return os.WriteFile(dst, body, 0o644)
}

func restoreOrRemove(src, dst string) {
	if body, err := os.ReadFile(src); err == nil {
		os.WriteFile(dst, body, 0o644)
		return
	}
	if _, err := os.Stat(src + ".missing"); err == nil {
		os.Remove(dst)
	}
}
