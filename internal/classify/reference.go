package classify

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/domain"
)

const (
	pslSource      = "https://publicsuffix.org/list/public_suffix_list.dat"
	pslMinRules    = 8000
	pslMaxBytes    = 8 << 20
	pslHTTPTimeout = 30 * time.Second
)

type ManualCounts struct {
	Exclude int `json:"exclude"`
	CN      int `json:"cn"`
	GFW     int `json:"gfw"`
}

func (e *Engine) SyncManualRules() (ManualCounts, error) {
	cn := readDomainList(filepath.Join(e.Config.StateDir, "manual-cn.txt"))
	gfw := readDomainList(filepath.Join(e.Config.StateDir, "manual-gfw.txt"))
	exclude := readDomainList(filepath.Join(e.Config.StateDir, "manual-exclude.txt"))

	overrides := make(map[string]string, len(cn)+len(gfw)+len(exclude))
	for name := range gfw {
		overrides[name] = OverrideGFW
	}
	for name := range cn {
		overrides[name] = OverrideCN
	}
	for name := range exclude {
		overrides[name] = OverrideExclude
	}
	counts := ManualCounts{}
	for _, kind := range overrides {
		switch kind {
		case OverrideExclude:
			counts.Exclude++
		case OverrideCN:
			counts.CN++
		case OverrideGFW:
			counts.GFW++
		}
	}
	return counts, e.Store.ReplaceManualOverrides(overrides)
}

func readDomainList(path string) map[string]struct{} {
	out := map[string]struct{}{}
	file, err := os.Open(path)
	if err != nil {
		return out
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		name := domain.Normalize(sc.Text())
		if name == "" || strings.HasPrefix(name, "#") {
			continue
		}
		out[name] = struct{}{}
	}
	return out
}

type PSLUpdate struct {
	OK        bool   `json:"ok"`
	Source    string `json:"source,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	RuleCount int    `json:"rule_count,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

func (e *Engine) UpdateReferenceData() PSLUpdate {
	dir := filepath.Join(e.Config.StateDir, "psl-data")
	target := e.Config.PSLPath
	if target == "" {
		target = filepath.Join(dir, "public_suffix_list.dat")
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return PSLUpdate{Reason: fmt.Sprintf("PSL 目录不可写，已保留旧版本: %v", err)}
	}
	text, err := fetchPSL()
	if err != nil {
		return PSLUpdate{Reason: fmt.Sprintf("PSL 更新失败，已保留旧版本: %v", err)}
	}
	parsed := domain.ParsePSL(text, pslSource)
	if parsed.Len() < pslMinRules {
		return PSLUpdate{Reason: fmt.Sprintf("PSL 条目异常（解析到 %d 条，低于 %d），已保留旧版本",
			parsed.Len(), pslMinRules)}
	}
	digest := sha256.Sum256([]byte(text))
	temp := target + ".tmp"
	if err := os.WriteFile(temp, []byte(text), 0o644); err != nil {
		return PSLUpdate{Reason: fmt.Sprintf("PSL 落盘失败，已保留旧版本: %v", err)}
	}
	if err := os.Rename(temp, target); err != nil {
		os.Remove(temp)
		return PSLUpdate{Reason: fmt.Sprintf("PSL 替换失败，已保留旧版本: %v", err)}
	}
	e.psl = nil
	update := PSLUpdate{
		OK: true, Source: pslSource, UpdatedAt: e.unixNow(),
		SHA256: hex.EncodeToString(digest[:]), RuleCount: parsed.Len(),
	}
	if meta, err := json.MarshalIndent(update, "", "  "); err == nil {
		os.WriteFile(filepath.Join(filepath.Dir(target), "meta.json"), meta, 0o644)
	}
	return update
}

func fetchPSL() (string, error) {
	client := &http.Client{Timeout: pslHTTPTimeout}
	resp, err := client.Get(pslSource)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, pslMaxBytes))
	if err != nil {
		return "", err
	}
	return string(body), nil
}
