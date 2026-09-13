package cdnrules

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/cidrutil"
)

const Schema = "cdn-direct/1"

const (
	tagProvider = "P"
	tagDomain   = "D"
	tagNet      = "N"

	placeMainland = "cn"
	placeOffshore = "off"
)

func Parse(r io.Reader) (*Set, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var (
		generated  time.Time
		schemaSeen bool
		order      []string
		byID       = make(map[string]*Provider)
		line       int
	)
	get := func(id string, ln int) (*Provider, error) {
		p, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("第 %d 行引用了未声明的 provider %q", ln, id)
		}
		return p, nil
	}
	for sc.Scan() {
		line++
		text := strings.TrimRight(sc.Text(), "\r")
		if strings.HasPrefix(text, "#") {
			key, value, ok := headerField(text)
			if !ok {
				continue
			}
			switch key {
			case "schema":
				if value != Schema {
					return nil, fmt.Errorf("规则集 schema 为 %q，本程序只认 %q", value, Schema)
				}
				schemaSeen = true
			case "generated-at":
				secs, err := strconv.ParseInt(value, 10, 64)
				if err != nil || secs <= 0 {
					return nil, fmt.Errorf("generated-at 不是正整数: %q", value)
				}
				generated = time.Unix(secs, 0).UTC()
			}
			continue
		}
		if strings.TrimSpace(text) == "" {
			continue
		}
		fields := strings.Split(text, "\t")
		switch fields[0] {
		case tagProvider:
			if len(fields) != 3 {
				return nil, fmt.Errorf("第 %d 行 provider 需要 3 列，实得 %d", line, len(fields))
			}
			id := strings.TrimSpace(fields[1])
			if id == "" {
				return nil, fmt.Errorf("第 %d 行 provider id 为空", line)
			}
			if _, dup := byID[id]; dup {
				return nil, fmt.Errorf("第 %d 行 provider %q 重复声明", line, id)
			}
			byID[id] = &Provider{ID: id, Name: strings.TrimSpace(fields[2])}
			order = append(order, id)
		case tagDomain:
			if len(fields) != 3 {
				return nil, fmt.Errorf("第 %d 行 domain 需要 3 列，实得 %d", line, len(fields))
			}
			p, err := get(strings.TrimSpace(fields[1]), line)
			if err != nil {
				return nil, err
			}
			name := normalize(fields[2])
			if name == "" {
				return nil, fmt.Errorf("第 %d 行 domain 为空", line)
			}
			p.Domains = append(p.Domains, name)
		case tagNet:
			if len(fields) != 4 {
				return nil, fmt.Errorf("第 %d 行 net 需要 4 列，实得 %d", line, len(fields))
			}
			p, err := get(strings.TrimSpace(fields[1]), line)
			if err != nil {
				return nil, err
			}
			prefix, err := cidrutil.ParsePrefix(strings.TrimSpace(fields[3]))
			if err != nil {
				return nil, fmt.Errorf("第 %d 行前缀无效: %w", line, err)
			}
			switch strings.TrimSpace(fields[2]) {
			case placeMainland:
				p.Mainland = append(p.Mainland, prefix)
			case placeOffshore:
				p.Offshore = append(p.Offshore, prefix)
			default:
				return nil, fmt.Errorf("第 %d 行归属标记应为 %s 或 %s", line, placeMainland, placeOffshore)
			}
		default:
			return nil, fmt.Errorf("第 %d 行标记 %q 无法识别", line, fields[0])
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !schemaSeen {
		return nil, fmt.Errorf("规则集缺少 schema 头，拒绝当作 %s 解析", Schema)
	}
	if generated.IsZero() {
		return nil, fmt.Errorf("规则集缺少 generated-at 头")
	}
	providers := make([]Provider, 0, len(order))
	for _, id := range order {
		providers = append(providers, *byID[id])
	}
	return New(generated, providers), nil
}

func Load(path string) (*Set, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

func Render(w io.Writer, generatedAt time.Time, providers []Provider) error {
	sorted := append([]Provider(nil), providers...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	domains, nets := 0, 0
	for i := range sorted {
		sorted[i].Domains = dedupeDomains(sorted[i].Domains)
		sorted[i].Mainland = cidrutil.CollapsePrefixes(sorted[i].Mainland)
		sorted[i].Offshore = cidrutil.CollapsePrefixes(sorted[i].Offshore)
		domains += len(sorted[i].Domains)
		nets += len(sorted[i].Mainland) + len(sorted[i].Offshore)
	}
	bw := bufio.NewWriterSize(w, 256*1024)
	fmt.Fprintf(bw, "# schema: %s\n", Schema)
	fmt.Fprintf(bw, "# generated-at: %d\n", generatedAt.UTC().Unix())
	fmt.Fprintf(bw, "# providers: %d\n", len(sorted))
	fmt.Fprintf(bw, "# domains: %d\n", domains)
	fmt.Fprintf(bw, "# prefixes: %d\n", nets)
	for _, p := range sorted {
		fmt.Fprintf(bw, "%s\t%s\t%s\n", tagProvider, p.ID, p.Name)
	}
	for _, p := range sorted {
		for _, d := range p.Domains {
			fmt.Fprintf(bw, "%s\t%s\t%s\n", tagDomain, p.ID, d)
		}
	}
	for _, p := range sorted {
		for _, n := range p.Mainland {
			fmt.Fprintf(bw, "%s\t%s\t%s\t%s\n", tagNet, p.ID, placeMainland, n)
		}
		for _, n := range p.Offshore {
			fmt.Fprintf(bw, "%s\t%s\t%s\t%s\n", tagNet, p.ID, placeOffshore, n)
		}
	}
	return bw.Flush()
}

func headerField(text string) (string, string, bool) {
	body := strings.TrimSpace(strings.TrimPrefix(text, "#"))
	colon := strings.IndexByte(body, ':')
	if colon < 0 {
		return "", "", false
	}
	return strings.TrimSpace(body[:colon]), strings.TrimSpace(body[colon+1:]), true
}

func dedupeDomains(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, d := range in {
		key := normalize(d)
		if key == "" {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
