package rulesync

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/dns-stack/dns-stack/internal/cidrutil"
)

var domainRe = regexp.MustCompile(
	`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out, sc.Err()
}

func ValidDomain(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	return domainRe.MatchString(name)
}

func CheckDomains(path string) error {
	lines, err := readLines(path)
	if err != nil {
		return err
	}
	var bad []string
	for _, line := range lines {
		if !ValidDomain(line) {
			bad = append(bad, line)
			if len(bad) >= 5 {
				break
			}
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("非法域名: %s", strings.Join(bad, ", "))
	}
	return nil
}

func CleanCIDRFile(src, dst string) error {
	prefixes, err := cidrutil.ReadPrefixFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, []byte(cidrutil.Render(cidrutil.CollapsePrefixes(prefixes))), 0o644)
}

func CheckDisjoint(cnPath, pollutedPath string) error {
	cn, err := cidrutil.ReadPrefixFile(cnPath)
	if err != nil {
		return err
	}
	polluted, err := cidrutil.ReadPrefixFile(pollutedPath)
	if err != nil {
		return err
	}
	if left, right, overlap := cidrutil.FirstOverlap(cn, polluted); overlap {
		return fmt.Errorf("CN CIDR 与污染 CIDR 存在重叠: %s <-> %s", left, right)
	}
	return nil
}

func MergePolluted(remotePath, localIPsPath, localCIDRsPath, outPath string) error {
	var prefixes []netip.Prefix
	for _, path := range []string{remotePath, localCIDRsPath} {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			continue
		}
		items, err := cidrutil.ReadPrefixFile(path)
		if err != nil {
			return err
		}
		prefixes = append(prefixes, items...)
	}
	if localIPsPath != "" {
		if lines, err := readLines(localIPsPath); err == nil {
			for _, line := range lines {
				addr, err := netip.ParseAddr(strings.TrimSpace(line))
				if err != nil {
					continue
				}
				addr = addr.Unmap()
				prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			}
		}
	}
	return os.WriteFile(outPath, []byte(cidrutil.Render(cidrutil.CollapsePrefixes(prefixes))), 0o644)
}

func CheckRuleOverlap(cnPath, gfwPath string) error {
	cn, err := readLines(cnPath)
	if err != nil {
		return err
	}
	gfw, err := readLines(gfwPath)
	if err != nil {
		return err
	}
	return CheckRuleSets(cn, gfw)
}

func CheckRuleSets(cn, gfw []string) error {
	marked := make(map[string]struct{}, len(gfw))
	for _, name := range gfw {
		if name = strings.TrimSpace(name); name != "" {
			marked[name] = struct{}{}
		}
	}
	var exact, unreachable []string
	for _, child := range cn {
		child = strings.TrimSpace(child)
		if child == "" {
			continue
		}
		if _, ok := marked[child]; ok {
			exact = append(exact, child)
			continue
		}
		if parent := suffixHit(child, marked); parent != "" {
			unreachable = append(unreachable, fmt.Sprintf("(%s, %s)", child, parent))
		}
	}
	if len(exact) > 0 {
		sort.Strings(exact)
		return fmt.Errorf("CN/GFW 存在精确交集: %s 等 %d 个", strings.Join(head(exact, 5), ", "), len(exact))
	}
	if len(unreachable) > 0 {
		sort.Strings(unreachable)
		return fmt.Errorf("CN 子域会被 GFW 父规则覆盖: [%s] 等 %d 组",
			strings.Join(head(unreachable, 5), ", "), len(unreachable))
	}
	return nil
}

func suffixHit(name string, marked map[string]struct{}) string {
	rest := name
	for {
		dot := strings.IndexByte(rest, '.')
		if dot < 0 {
			return ""
		}
		rest = rest[dot+1:]
		if _, ok := marked[rest]; ok {
			return rest
		}
	}
}

func head(values []string, n int) []string {
	if len(values) > n {
		return values[:n]
	}
	return values
}
