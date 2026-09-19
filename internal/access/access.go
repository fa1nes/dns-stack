package access

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/cidrutil"
	"github.com/dns-stack/dns-stack/internal/domain"
)

const (
	BlocklistFile = "blocklist.txt"
	ACLFile       = "acl.txt"

	blocklistHeader = "# dns-stack 域名黑名单：命中的查询由 mosproxy 直接回 NXDOMAIN，不出本机\n" +
		"# 每行一个域名，匹配包含其全部子域。# 开头为注释。\n"
	aclHeader = "# dns-stack 访问控制：只有这里列出的网段能查询 DoH/DoT/DoQ 入口\n" +
		"# 每行一个 CIDR 或单个地址。空文件 = 不启用访问控制（全网可查）。\n"
)

type Store struct {
	StateDir string
}

func (s Store) blocklistPath() string { return filepath.Join(s.StateDir, BlocklistFile) }
func (s Store) aclPath() string       { return filepath.Join(s.StateDir, ACLFile) }

func readEntries(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()
	var out []string
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func writeEntries(path, header string, entries []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString(header)
	b.WriteString("# 最后更新: " + time.Now().Format("2006-01-02 15:04:05") + "\n\n")
	for _, entry := range entries {
		b.WriteString(entry)
		b.WriteByte('\n')
	}
	temp := path + ".new"
	if err := os.WriteFile(temp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		os.Remove(temp)
		return err
	}
	return nil
}

func (s Store) EnsureFiles() error {
	for _, item := range [][2]string{
		{s.blocklistPath(), blocklistHeader},
		{s.aclPath(), aclHeader},
	} {
		if _, err := os.Stat(item[0]); err == nil {
			continue
		}
		if err := writeEntries(item[0], item[1], nil); err != nil {
			return err
		}
	}
	return nil
}

func (s Store) MissingFiles() []string {
	var missing []string
	if _, err := os.Stat(s.blocklistPath()); err != nil {
		missing = append(missing, s.blocklistPath())
	}
	return missing
}

func (s Store) Blocklist() ([]string, error) { return readEntries(s.blocklistPath()) }

func (s Store) ACL() ([]netip.Prefix, error) {
	entries, err := readEntries(s.aclPath())
	if err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		prefix, err := cidrutil.ParsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("%s 里有非法条目 %q: %w", ACLFile, entry, err)
		}
		out = append(out, prefix)
	}
	return out, nil
}

func normalizeDomain(name string) (string, error) {
	value := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if value == "" {
		return "", fmt.Errorf("域名为空")
	}
	if !domain.IsWellFormed(value) {
		return "", fmt.Errorf("域名格式非法: %s", name)
	}
	if !strings.Contains(value, ".") {
		return "", fmt.Errorf("拒绝拉黑顶级域 %q——它会连带屏蔽该 TLD 下的一切", value)
	}
	return value, nil
}

func (s Store) AddBlocked(names []string) (added []string, err error) {
	current, err := s.Blocklist()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(current))
	for _, item := range current {
		seen[item] = struct{}{}
	}
	for _, raw := range names {
		value, err := normalizeDomain(raw)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[value]; dup {
			continue
		}
		seen[value] = struct{}{}
		current = append(current, value)
		added = append(added, value)
	}
	if len(added) == 0 {
		return nil, nil
	}
	sort.Strings(current)
	return added, writeEntries(s.blocklistPath(), blocklistHeader, current)
}

func (s Store) RemoveBlocked(names []string) (removed []string, err error) {
	current, err := s.Blocklist()
	if err != nil {
		return nil, err
	}
	drop := make(map[string]struct{}, len(names))
	for _, raw := range names {
		drop[strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))] = struct{}{}
	}
	kept := make([]string, 0, len(current))
	for _, item := range current {
		if _, gone := drop[item]; gone {
			removed = append(removed, item)
			continue
		}
		kept = append(kept, item)
	}
	if len(removed) == 0 {
		return nil, nil
	}
	return removed, writeEntries(s.blocklistPath(), blocklistHeader, kept)
}

func (s Store) SetACL(entries []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		prefix, err := cidrutil.ParsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("非法条目 %q: %w", entry, err)
		}
		prefixes = append(prefixes, prefix)
	}
	prefixes = cidrutil.CollapsePrefixes(prefixes)
	rendered := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		rendered = append(rendered, prefix.String())
	}
	return prefixes, writeEntries(s.aclPath(), aclHeader, rendered)
}

func (s Store) AddACL(entries []string) ([]netip.Prefix, error) {
	current, err := s.ACL()
	if err != nil {
		return nil, err
	}
	rendered := make([]string, 0, len(current)+len(entries))
	for _, prefix := range current {
		rendered = append(rendered, prefix.String())
	}
	rendered = append(rendered, entries...)
	return s.SetACL(rendered)
}

func (s Store) RemoveACL(entries []string) ([]netip.Prefix, error) {
	current, err := s.ACL()
	if err != nil {
		return nil, err
	}
	var drop []netip.Prefix
	for _, entry := range entries {
		prefix, err := cidrutil.ParsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("非法条目 %q: %w", entry, err)
		}
		drop = append(drop, prefix)
	}
	kept := cidrutil.Subtract(current, drop)
	rendered := make([]string, 0, len(kept))
	for _, prefix := range kept {
		rendered = append(rendered, prefix.String())
	}
	return s.SetACL(rendered)
}
