package access

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/cidrutil"
	"github.com/dns-stack/dns-stack/internal/domain"
	"github.com/dns-stack/dns-stack/internal/statefile"
)

const (
	BlocklistFile   = "blocklist.txt"
	ACLFile         = "acl.txt"
	ACLDisabledFile = "acl.disabled"
	RouteCNFile     = "manual-cn-zones.txt"
	RouteHKFile     = "manual-gfw.txt"

	blocklistHeader = "# dns-stack 域名黑名单：命中的查询由 mosproxy 直接回 NXDOMAIN，不出本机\n" +
		"# 每行一个域名，匹配包含其全部子域。# 开头为注释。\n"
	aclHeader = "# dns-stack 访问控制：只有这里列出的网段能查询 DoH/DoT/DoQ 入口\n" +
		"# 每行一个 CIDR 或单个地址。空文件 = 不启用访问控制（全网可查）。\n"
	routeCNHeader = "# dns-stack 国内解析名单：这些域名的权威服务器从国内直连查询，并带上客户端子网\n" +
		"# 每行一个域名，包含全部子域。由面板或 dns-stack route 维护。\n"
	routeHKHeader = "# dns-stack 香港解析名单：这些域名整条交给香港 Unbound 解析\n" +
		"# 每行一个域名，包含全部子域。由面板或 dns-stack route 维护。\n"
)

type RouteList string

const (
	RouteCN RouteList = "cn"
	RouteHK RouteList = "hk"
)

func ParseRouteList(raw string) (RouteList, error) {
	switch RouteList(strings.ToLower(strings.TrimSpace(raw))) {
	case RouteCN:
		return RouteCN, nil
	case RouteHK:
		return RouteHK, nil
	}
	return "", fmt.Errorf("名单只能是 cn（国内解析）或 hk（香港解析），收到 %q", raw)
}

func (l RouteList) Other() RouteList {
	if l == RouteCN {
		return RouteHK
	}
	return RouteCN
}

func (l RouteList) file() (string, string) {
	if l == RouteCN {
		return RouteCNFile, routeCNHeader
	}
	return RouteHKFile, routeHKHeader
}

type Store struct {
	StateDir string
}

func (s Store) blocklistPath() string { return filepath.Join(s.StateDir, BlocklistFile) }
func (s Store) aclPath() string       { return filepath.Join(s.StateDir, ACLFile) }
func (s Store) aclOffPath() string    { return filepath.Join(s.StateDir, ACLDisabledFile) }

func (s Store) ACLDisabled() bool {
	_, err := os.Stat(s.aclOffPath())
	return err == nil
}

func (s Store) SetACLDisabled(disabled bool) error {
	if disabled {
		return statefile.WriteAtomic(s.aclOffPath(), []byte(time.Now().Format(time.RFC3339)+"\n"), 0o644)
	}
	if err := os.Remove(s.aclOffPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s Store) EnforcedACL() ([]netip.Prefix, error) {
	if s.ACLDisabled() {
		return nil, nil
	}
	return s.ACL()
}

func readEntries(path string) ([]string, error) {
	lines, err := statefile.Lines(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	return lines, err
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
	return statefile.WriteAtomic(path, []byte(b.String()), 0o644)
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
		return "", fmt.Errorf("不接受顶级域 %q——它会连带影响这个后缀下的所有域名", value)
	}
	return value, nil
}

func addEntries(path, header string, current, names []string) (added []string, err error) {
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
		added = append(added, value)
	}
	if len(added) == 0 {
		return nil, nil
	}
	return added, editEntries(path, header, nil, added)
}

func entryKey(line string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(line), "."))
}

func removeEntries(path, header string, current, names []string) (removed []string, err error) {
	drop := make(map[string]struct{}, len(names))
	for _, raw := range names {
		drop[entryKey(raw)] = struct{}{}
	}
	for _, item := range current {
		if _, gone := drop[entryKey(item)]; gone {
			removed = append(removed, item)
		}
	}
	if len(removed) == 0 {
		return nil, nil
	}
	return removed, editEntries(path, header, drop, nil)
}

func editEntries(path, header string, drop map[string]struct{}, add []string) error {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) || (err == nil && len(strings.TrimSpace(string(raw))) == 0) {
		return writeEntries(path, header, add)
	}
	if err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	var b strings.Builder
	for _, line := range strings.SplitAfter(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case line == "":
			continue
		case strings.HasPrefix(trimmed, "# 最后更新: "):
			b.WriteString("# 最后更新: " + time.Now().Format("2006-01-02 15:04:05") + "\n")
			continue
		case trimmed != "" && !strings.HasPrefix(trimmed, "#"):
			if _, gone := drop[entryKey(trimmed)]; gone {
				continue
			}
		}
		b.WriteString(line)
	}
	if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
		b.WriteByte('\n')
	}
	for _, entry := range add {
		b.WriteString(entry + "\n")
	}
	return statefile.WriteAtomic(path, []byte(b.String()), mode)
}

func (s Store) AddBlocked(names []string) ([]string, error) {
	current, err := s.Blocklist()
	if err != nil {
		return nil, err
	}
	return addEntries(s.blocklistPath(), blocklistHeader, current, names)
}

func (s Store) RemoveBlocked(names []string) ([]string, error) {
	current, err := s.Blocklist()
	if err != nil {
		return nil, err
	}
	return removeEntries(s.blocklistPath(), blocklistHeader, current, names)
}

func (s Store) routePath(list RouteList) (string, string) {
	name, header := list.file()
	return filepath.Join(s.StateDir, name), header
}

func (s Store) Routes(list RouteList) ([]string, error) {
	path, _ := s.routePath(list)
	return readEntries(path)
}

func (s Store) AddRoutes(list RouteList, names []string) (added, moved []string, err error) {
	current, err := s.Routes(list)
	if err != nil {
		return nil, nil, err
	}
	path, header := s.routePath(list)
	if added, err = addEntries(path, header, current, names); err != nil || len(added) == 0 {
		return added, nil, err
	}
	moved, err = s.RemoveRoutes(list.Other(), added)
	return added, moved, err
}

func (s Store) RemoveRoutes(list RouteList, names []string) ([]string, error) {
	current, err := s.Routes(list)
	if err != nil {
		return nil, err
	}
	path, header := s.routePath(list)
	return removeEntries(path, header, current, names)
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
