package pipeline

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/dnswire"
	"github.com/dns-stack/dns-stack/internal/infra"
	"github.com/dns-stack/dns-stack/internal/ipset"
)

const manualNSLimit = 8

type authorityPair struct {
	Zone string
	IP   string
	RTO  int
}

func (r *Runtime) dumpInfra(ctx context.Context) (infra.Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, r.Config.UnboundCtl, "dump_infra").Output()
	if err != nil {
		return infra.Snapshot{}, err
	}
	return infra.Parse(strings.NewReader(string(out)))
}

func (r *Runtime) resolver() string {
	return net.JoinHostPort(r.Config.Resolver, fmt.Sprint(r.Config.ResolverPort))
}

func (r *Runtime) query(ctx context.Context, name string, qtype uint16) (*dnswire.Msg, []byte, error) {
	packet, err := dnswire.BuildQuery(uint16(time.Now().UnixNano()), name, qtype)
	if err != nil {
		return nil, nil, err
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", r.resolver())
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(4 * time.Second)
	if due, ok := ctx.Deadline(); ok && due.Before(deadline) {
		deadline = due
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(packet); err != nil {
		return nil, nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, nil, err
	}
	raw := buf[:n]
	msg, err := dnswire.Unpack(raw)
	if err != nil {
		return nil, nil, err
	}
	return msg, raw, nil
}

func (r *Runtime) nsNames(ctx context.Context, zone string) []string {
	msg, raw, err := r.query(ctx, zone, dnswire.TypeNS)
	if err != nil {
		return nil
	}
	var out []string
	for _, section := range [][]dnswire.RR{msg.Answers, msg.Authorities} {
		for _, rr := range section {
			if rr.Type != dnswire.TypeNS {
				continue
			}
			name, ok := rr.TargetName(raw)
			if !ok {
				continue
			}
			out = append(out, strings.TrimSuffix(name, "."))
		}
		if len(out) > 0 {
			break
		}
	}
	if len(out) > manualNSLimit {
		out = out[:manualNSLimit]
	}
	return out
}

func (r *Runtime) addrsOf(ctx context.Context, name string) []string {
	msg, _, err := r.query(ctx, name, dnswire.TypeA)
	if err != nil {
		return nil
	}
	var out []string
	for _, rr := range msg.Answers {
		if addr, ok := rr.A(); ok {
			out = append(out, addr.String())
		}
	}
	return out
}

func manualZones(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	var out []string
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.ToLower(line))
	}
	return out
}

func (r *Runtime) collectAuthorityPairs(ctx context.Context) (string, int, error) {
	snapshot, err := r.dumpInfra(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("读不到 Unbound infra cache: %w", err)
	}
	seen := map[authorityPair]struct{}{}
	zones := map[string]struct{}{}
	for _, entry := range snapshot.Entries {
		if !entry.IP.Is4() {
			continue
		}
		zone := strings.ToLower(strings.TrimSuffix(entry.Zone, "."))
		if zone == "" || zone == "." {
			continue
		}
		rto := -1
		if entry.HasRTO {
			rto = entry.RTO
		}
		seen[authorityPair{Zone: zone, IP: entry.IP.String(), RTO: rto}] = struct{}{}
		zones[zone] = struct{}{}
	}

	resolved, unresolved := 0, []string{}
	manual := manualZones(r.Config.Path("manual-cn-zones.txt"))
	for _, zone := range manual {
		hit := false
		for _, ns := range r.nsNames(ctx, zone) {
			for _, addr := range r.addrsOf(ctx, ns) {
				seen[authorityPair{Zone: zone, IP: addr, RTO: 0}] = struct{}{}
				zones[zone] = struct{}{}
				hit = true
			}
		}
		if hit {
			resolved++
		} else {
			unresolved = append(unresolved, zone)
		}
		if ctx.Err() != nil {
			break
		}
	}
	if len(manual) > 0 {
		r.Infof("已并入人工补充区域 %d/%d 个", resolved, len(manual))
	}
	if len(unresolved) > 0 {
		r.Warnf("人工补充区域本轮取不到权威地址：%s", strings.Join(unresolved, " "))
		r.Warnf("  这些域名本轮不进直连集合，解析会走隧道；下一轮自动重试")
	}

	lines := make([]string, 0, len(seen))
	for pair := range seen {
		lines = append(lines, fmt.Sprintf("%s %s %d", pair.Zone, pair.IP, pair.RTO))
	}
	sort.Strings(lines)
	r.Infof("候选区域 %d 个，(区域, 权威地址) 记录 %d 条", len(zones), len(lines))
	return strings.Join(lines, "\n") + "\n", len(zones), nil
}

func countPrefixes(path string) int {
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()
	count := 0
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		count++
	}
	return count
}

func loadPrefixes(path string) ([]netip.Prefix, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	loaded, err := ipset.LoadReader(file, ipset.LoadOptions{})
	if err != nil {
		return nil, err
	}
	return loaded.Set.Prefixes(), nil
}

func (r *Runtime) commitAuthoritySet(ctx context.Context, live, staged string) error {
	minRatio := r.Config.Int("GUARD_MIN_RATIO", 40)
	old, fresh := countPrefixes(live), countPrefixes(staged)
	if old >= 20 && fresh < old*minRatio/100 {
		os.Remove(staged)
		return fmt.Errorf("墙内权威网段从 %d 条骤降到 %d 条（低于 %d%% 阈值），拒绝写入；"+
			"最可能是 Unbound infra cache 刚被清空，等下一轮自然恢复", old, fresh, minRatio)
	}
	prefixes, err := loadPrefixes(staged)
	if err != nil {
		os.Remove(staged)
		return err
	}
	if err := r.LoadNFTSet(ctx, r.Config.AuthoritySet, prefixes); err != nil {
		os.Remove(staged)
		return err
	}
	if err := os.Rename(staged, live); err != nil {
		return err
	}
	r.Infof("墙内权威集合已更新：%d 条网段", fresh)
	return nil
}

func countECSLines(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "send-client-subnet:") {
			count++
		}
	}
	return count
}

func sameFile(a, b string) bool {
	left, err := os.ReadFile(a)
	if err != nil {
		return false
	}
	right, err := os.ReadFile(b)
	if err != nil {
		return false
	}
	return string(left) == string(right)
}

func unboundCheckConf(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "unbound-checkconf").Run()
}

func (r *Runtime) commitECSConf(ctx context.Context, staged string) error {
	live := r.Config.ECSConfPath
	fresh, old := countECSLines(staged), countECSLines(live)
	minRatio := r.Config.Int("GUARD_MIN_RATIO", 40)

	switch {
	case fresh == 0:
		os.Remove(staged)
		r.Warnf("ECS 白名单为空，保留现有的 %d 条不动", old)
		r.Warnf("  空白名单会让所有权威都收不到客户端子网，国内 CDN 调度会静默退化")
		return nil
	case old >= 20 && fresh < old*minRatio/100:
		os.Remove(staged)
		r.Warnf("ECS 白名单从 %d 条骤降到 %d 条，保留现有内容", old, fresh)
		return nil
	case sameFile(staged, live):
		os.Remove(staged)
		r.Infof("ECS 白名单无变化（%d 条），跳过重载", fresh)
		return nil
	}

	if err := unboundCheckConf(ctx); err != nil {
		os.Remove(staged)
		r.Warnf("现网 unbound 配置本身就没通过 checkconf，跳过 ECS 白名单更新")
		return nil
	}
	backup := live + ".prev"
	if data, err := os.ReadFile(live); err == nil {
		os.WriteFile(backup, data, 0o644)
	}
	if err := os.Chmod(staged, 0o644); err != nil {
		os.Remove(staged)
		return err
	}
	if err := os.Rename(staged, live); err != nil {
		os.Remove(staged)
		return err
	}
	if err := unboundCheckConf(ctx); err != nil {
		if data, readErr := os.ReadFile(backup); readErr == nil {
			os.WriteFile(live, data, 0o644)
		} else {
			os.Remove(live)
		}
		return fmt.Errorf("新的 ECS 白名单没通过 unbound-checkconf，已回滚: %w", err)
	}
	reload := exec.CommandContext(ctx, "unbound-control", "reload_keep_cache")
	if err := reload.Run(); err != nil {
		r.Warnf("ECS 白名单已写入（%d 条）但热重载失败，下次重启生效", fresh)
		return nil
	}
	r.Infof("ECS 白名单已更新：%d -> %d 条（已热重载，缓存保留）", old, fresh)
	return nil
}
