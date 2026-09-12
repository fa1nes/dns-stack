package classify

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/domain"
	"github.com/dns-stack/dns-stack/internal/geoaudit"
	"github.com/dns-stack/dns-stack/internal/ipset"
	"github.com/dns-stack/dns-stack/internal/rulesync"
)

const (
	minCNCIDRs        = 3000
	direct4SourceName = "cn-direct4-apnic"
	pollutedSource    = "cn-resolver-probe"
	pullTimeout       = 30 * time.Second
)

type PullResult struct {
	Domains        int    `json:"domains"`
	NewCandidates  int    `json:"new_candidates"`
	Direct4        int    `json:"direct4_prefixes"`
	CNCIDRs        int    `json:"cn_cidrs"`
	PollutedCIDRs  int    `json:"polluted_cidrs"`
	DisputedPrefix int    `json:"disputed_prefixes"`
	DisputedNote   string `json:"disputed_note,omitempty"`
}

type pullPayload struct {
	Domains       []collectorCandidate `json:"domains"`
	PollutedCIDRs []string             `json:"polluted_cidrs"`
	CNCIDRs       []string             `json:"cn_cidrs"`
	GeoDisputed   string               `json:"geo_disputed"`
}

type collectorCandidate struct {
	Domain string `json:"domain"`
}

func (e *Engine) fetchFromCN() (pullPayload, error) {
	var payload pullPayload
	cmd := exec.Command("ssh", "-n",
		"-i", e.Config.PullKeyPath,
		"-p", strconv.Itoa(e.Config.CNSSHPort),
		"-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		fmt.Sprintf("%s@%s", e.Config.CNSSHUser, e.Config.CNResolver))
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return payload, fmt.Errorf("无法启动 ssh: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return payload, fmt.Errorf("SSH 拉取失败: %v: %s", err, trim(stderr.String(), 300))
		}
	case <-time.After(pullTimeout):
		cmd.Process.Kill()
		return payload, fmt.Errorf("连接国内服务器(%s)超时，检查 WireGuard 隧道是否正常", e.Config.CNResolver)
	}
	if err := json.Unmarshal([]byte(stdout.String()), &payload); err != nil {
		return payload, fmt.Errorf("国内服务器返回的不是预期 JSON: %s", trim(stdout.String(), 200))
	}
	return payload, nil
}

func trim(text string, limit int) string {
	text = strings.TrimSpace(text)
	if len(text) > limit {
		return text[:limit]
	}
	return text
}

func (e *Engine) Pull() (PullResult, error) {
	var result PullResult
	payload, err := e.fetchFromCN()
	if err != nil {
		return result, err
	}

	names := make([]string, 0, len(payload.Domains))
	seen := make(map[string]struct{}, len(payload.Domains))
	for _, row := range payload.Domains {
		name := domain.Normalize(row.Domain)
		if name == "" || !rulesync.ValidDomain(name) {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	result.Domains = len(names)

	var v4 []string
	for _, cidr := range payload.CNCIDRs {
		if !strings.Contains(cidr, ":") {
			v4 = append(v4, cidr)
		}
	}
	result.CNCIDRs = len(payload.CNCIDRs)
	result.PollutedCIDRs = len(payload.PollutedCIDRs)

	restoreDirect4 := func() {}
	if len(v4) >= minCNCIDRs {
		prefixes, err := globalPrefixesOf(v4)
		if err != nil {
			return result, err
		}
		if len(prefixes) < minCNCIDRs {
			return result, fmt.Errorf("国内返回的 IPv4 CIDR 仅 %d 条（过滤保留段后），低于护栏 %d 条",
				len(prefixes), minCNCIDRs)
		}
		restoreDirect4, err = e.writeDirect4Snapshot(prefixes)
		if err != nil {
			return result, err
		}
		result.Direct4 = len(prefixes)
		if err := e.Store.ReplaceCIDRs("cn", map[string][]string{direct4SourceName: payload.CNCIDRs}); err != nil {
			restoreDirect4()
			return result, err
		}
	}
	result.DisputedPrefix, result.DisputedNote = e.storeDisputed(payload.GeoDisputed)

	if len(payload.PollutedCIDRs) > 0 {
		if err := e.Store.ReplaceCIDRs("polluted", map[string][]string{pollutedSource: payload.PollutedCIDRs}); err != nil {
			restoreDirect4()
			return result, err
		}
		e.invalidatePolluted()
	}
	if len(names) == 0 {
		return result, nil
	}
	inserted, err := e.Store.UpsertCandidates(names)
	if err != nil {
		restoreDirect4()
		return result, err
	}
	result.NewCandidates = inserted
	return result, nil
}

func (e *Engine) storeDisputed(body string) (int, string) {
	if strings.TrimSpace(body) == "" {
		return 0, "国内节点没有回传多源争议清单"
	}
	path := e.DisputedPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, "无法创建争议清单目录: " + err.Error()
	}
	temp := path + ".tmp"
	if err := os.WriteFile(temp, []byte(body), 0o644); err != nil {
		return 0, "写入争议清单失败: " + err.Error()
	}
	snapshot, err := geoaudit.LoadSnapshot(temp)
	if err != nil {
		os.Remove(temp)
		return 0, "回传的争议清单无法解析: " + err.Error()
	}
	if snapshot.Kind != geoaudit.KindDisputed {
		os.Remove(temp)
		return 0, fmt.Sprintf("回传清单声明的 kind 是 %q，期望 %q，拒绝按错误方向使用",
			snapshot.Kind, geoaudit.KindDisputed)
	}
	if len(snapshot.Sources) < geoaudit.MinSources {
		os.Remove(temp)
		return 0, fmt.Sprintf("回传清单只有 %d 个归属库参与交叉（至少 %d 个），不予采用",
			len(snapshot.Sources), geoaudit.MinSources)
	}
	if err := os.Rename(temp, path); err != nil {
		os.Remove(temp)
		return 0, "落盘争议清单失败: " + err.Error()
	}
	e.disputed = nil
	return snapshot.Prefixes, ""
}

func globalPrefixesOf(values []string) ([]string, error) {
	loaded, err := ipset.LoadReader(strings.NewReader(strings.Join(values, "\n")),
		ipset.LoadOptions{GlobalOnly: true})
	if err != nil {
		return nil, err
	}
	prefixes := loaded.Set.Prefixes()
	out := make([]string, len(prefixes))
	for i, p := range prefixes {
		out[i] = p.String()
	}
	return out, nil
}

func (e *Engine) writeDirect4Snapshot(prefixes []string) (restore func(), err error) {
	path := e.Config.Direct4Path
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	previous, readErr := os.ReadFile(path)
	restore = func() {
		if readErr != nil {
			os.Remove(path)
			return
		}
		os.WriteFile(path, previous, 0o644)
	}
	var body strings.Builder
	body.WriteString("# 由国内节点 APNIC direct4 快照原子同步，请勿手工编辑\n")
	for _, prefix := range prefixes {
		body.WriteString(prefix)
		body.WriteByte('\n')
	}
	temp := path + ".tmp"
	if err := os.WriteFile(temp, []byte(body.String()), 0o644); err != nil {
		return nil, err
	}
	if err := os.Rename(temp, path); err != nil {
		os.Remove(temp)
		return nil, err
	}
	e.direct4 = nil
	return restore, nil
}
