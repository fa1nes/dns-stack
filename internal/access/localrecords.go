package access

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dns-stack/dns-stack/internal/domain"
)

const (
	LocalRecordsFile = "local-records.txt"
	LocalRecordTTL   = 300

	localRecordsHeader = "# dns-stack 本地记录：这些名字由本机 Unbound 直接回答，不发起递归\n" +
		"# 每行「域名 类型 值」，类型只有 A / AAAA。只管这个名字本身，子域照常解析；\n" +
		"# 名字下没写的类型回「无记录」。由面板或 dns-stack local-record 维护。\n"
)

type LocalRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (r LocalRecord) String() string { return r.Name + " " + r.Type + " " + r.Value }

func (r LocalRecord) UnboundData() string {
	return fmt.Sprintf("%s. %d IN %s %s", r.Name, LocalRecordTTL, r.Type, r.Value)
}

func ParseLocalRecord(name, kind, value string) (LocalRecord, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if host == "" {
		return LocalRecord{}, fmt.Errorf("域名为空")
	}
	if !domain.IsWellFormed(host) || strings.HasPrefix(host, "*") {
		return LocalRecord{}, fmt.Errorf("域名格式非法: %s", name)
	}
	if !strings.Contains(host, ".") {
		return LocalRecord{}, fmt.Errorf("不接受单段名字 %q——写完整域名，如 nas.home.arpa", host)
	}
	kind = strings.ToUpper(strings.TrimSpace(kind))
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || addr.Zone() != "" {
		return LocalRecord{}, fmt.Errorf("%q 不是合法的 IP 地址", value)
	}
	switch kind {
	case "A":
		if !addr.Is4() && !addr.Is4In6() {
			return LocalRecord{}, fmt.Errorf("A 记录要填 IPv4 地址，收到 %s", value)
		}
		addr = addr.Unmap()
	case "AAAA":
		if !addr.Is6() || addr.Is4In6() {
			return LocalRecord{}, fmt.Errorf("AAAA 记录要填 IPv6 地址，收到 %s", value)
		}
	default:
		return LocalRecord{}, fmt.Errorf("类型只能是 A 或 AAAA，收到 %q", kind)
	}
	return LocalRecord{Name: host, Type: kind, Value: addr.String()}, nil
}

func (s Store) localRecordsPath() string { return filepath.Join(s.StateDir, LocalRecordsFile) }

func (s Store) LocalRecords() ([]LocalRecord, error) {
	lines, err := readEntries(s.localRecordsPath())
	if err != nil {
		return nil, err
	}
	out := make([]LocalRecord, 0, len(lines))
	seen := make(map[LocalRecord]struct{}, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("%s 里有看不懂的行 %q（应为「域名 类型 值」）", LocalRecordsFile, line)
		}
		record, err := ParseLocalRecord(fields[0], fields[1], fields[2])
		if err != nil {
			return nil, fmt.Errorf("%s 里有非法条目 %q: %w", LocalRecordsFile, line, err)
		}
		if _, dup := seen[record]; dup {
			continue
		}
		seen[record] = struct{}{}
		out = append(out, record)
	}
	return out, nil
}

func (s Store) writeLocalRecords(records []LocalRecord) error {
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Name != records[j].Name {
			return records[i].Name < records[j].Name
		}
		return records[i].Type < records[j].Type
	})
	lines := make([]string, 0, len(records))
	for _, record := range records {
		lines = append(lines, record.String())
	}
	return writeEntries(s.localRecordsPath(), localRecordsHeader, lines)
}

func (s Store) AddLocalRecord(record LocalRecord) (bool, error) {
	unlock, err := s.lockRoutes()
	if err != nil {
		return false, err
	}
	defer unlock()
	current, err := s.LocalRecords()
	if err != nil {
		return false, err
	}
	for _, item := range current {
		if item == record {
			return false, nil
		}
	}
	return true, s.writeLocalRecords(append(current, record))
}

func (s Store) RemoveLocalRecords(name, kind, value string) ([]LocalRecord, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	kind = strings.ToUpper(strings.TrimSpace(kind))
	if value != "" {
		if addr, err := netip.ParseAddr(strings.TrimSpace(value)); err == nil {
			value = addr.Unmap().String()
		}
	}
	unlock, err := s.lockRoutes()
	if err != nil {
		return nil, err
	}
	defer unlock()
	current, err := s.LocalRecords()
	if err != nil {
		return nil, err
	}
	var kept, removed []LocalRecord
	for _, item := range current {
		if item.Name == host && (kind == "" || item.Type == kind) && (value == "" || item.Value == value) {
			removed = append(removed, item)
			continue
		}
		kept = append(kept, item)
	}
	if len(removed) == 0 {
		return nil, nil
	}
	return removed, s.writeLocalRecords(kept)
}

func RecordsFor(records []LocalRecord, name string) []LocalRecord {
	var out []LocalRecord
	for _, record := range records {
		if record.Name == name {
			out = append(out, record)
		}
	}
	return out
}

func RenderUnboundLocal(records []LocalRecord) string {
	var b strings.Builder
	b.WriteString("# 由 dns-stack local-record 生成，手改会被覆盖；源文件是 /var/lib/dns-stack/" + LocalRecordsFile + "\n")
	b.WriteString("server:\n")
	for _, record := range records {
		fmt.Fprintf(&b, "    local-data: \"%s\"\n", record.UnboundData())
	}
	return b.String()
}

func (s Store) Shadowing(name string) (string, error) {
	blocked, err := s.Blocklist()
	if err != nil {
		return "", err
	}
	for _, line := range blocked {
		if suffix := entryKey(line); covers(suffix, name) {
			return "拦截名单里的 " + suffix, nil
		}
	}
	hk, err := s.Routes(RouteHK)
	if err != nil {
		return "", err
	}
	excluded, _ := readEntries(filepath.Join(s.StateDir, "manual-exclude.txt"))
	for _, suffix := range hk {
		if !covers(suffix, name) {
			continue
		}
		for _, line := range excluded {
			if covers(entryKey(line), name) {
				return "", nil
			}
		}
		return "香港解析名单里的 " + suffix, nil
	}
	return "", nil
}

func covers(suffix, name string) bool {
	return suffix != "" && (name == suffix || strings.HasSuffix(name, "."+suffix))
}
