package main

import (
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/dnswire"
	"github.com/dns-stack/dns-stack/internal/ecszone"
	"github.com/dns-stack/dns-stack/internal/ipset"
)

var ecsForwardDomains = []string{"www.qq.com", "www.iqiyi.com", "www.jd.com", "www.bilibili.com"}

type subnetAnswers struct {
	Domain string              `json:"domain"`
	ByNet  map[string][]string `json:"by_subnet"`
}

func (s subnetAnswers) comparable() bool { return len(s.ByNet) >= 2 }

func (s subnetAnswers) differentiated() bool {
	if !s.comparable() {
		return false
	}
	var first string
	for _, answers := range s.ByNet {
		key := strings.Join(answers, " ")
		if first == "" {
			first = key
			continue
		}
		if key != first {
			return true
		}
	}
	return false
}

type forwardGroup struct {
	Subnets        []string        `json:"subnets"`
	Comparable     int             `json:"comparable"`
	Differentiated int             `json:"differentiated"`
	Results        []subnetAnswers `json:"results"`
}

func cmdECSForward(args []string) error {
	fs := flag.NewFlagSet("ecs-forward", flag.ContinueOnError)
	state := fs.String("state", envOr("DNS_STACK_STATE", "/var/lib/dns-stack"), "状态目录")
	host := fs.String("host", envOr("MOSPROXY_DOT_HOST", "127.0.0.1"), "mosproxy DoT 地址")
	port := fs.Int("port", 853, "mosproxy DoT 端口")
	domainList := fs.String("domains", "", "逗号分隔的测试域名，留空用内置清单")
	seed := fs.Int64("seed", 1, "子网抽样种子")
	asJSON := fs.Bool("json", false, "输出 JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	domains := ecsForwardDomains
	if strings.TrimSpace(*domainList) != "" {
		domains = strings.Split(*domainList, ",")
		for i := range domains {
			domains[i] = strings.TrimSpace(domains[i])
		}
	}

	rows, err := ecszone.LoadRows(filepath.Join(*state, "ecs-ip-zone.txt"))
	if err != nil {
		return fmt.Errorf("读不到 ECS 分片表: %w", err)
	}
	directFile, err := os.Open(filepath.Join(*state, "chnroute", "direct4.txt"))
	if err != nil {
		return fmt.Errorf("读不到 direct4: %w", err)
	}
	direct, err := ipset.LoadReader(directFile, ipset.LoadOptions{GlobalOnly: true})
	directFile.Close()
	if err != nil {
		return err
	}
	if direct.Set.Len() == 0 {
		return fmt.Errorf("direct4 为空，抽不出可比较的客户端子网")
	}

	inside, outside := sampleSubnets(direct.Set, rows, *seed)
	if len(outside) == 0 {
		return fmt.Errorf("分片表已经覆盖了全部抽样地址，取不到表外样本；本判据需要表内表外各两个 /24 作对照")
	}

	server := net.JoinHostPort(*host, fmt.Sprint(*port))
	insideGroup := probeGroup(server, domains, inside)
	outsideGroup := probeGroup(server, domains, outside)

	verdict := "ok"
	if outsideGroup.Comparable > 0 && outsideGroup.Differentiated == 0 && insideGroup.Differentiated > 0 {
		verdict = "unmarked_networks_lose_ecs"
	}
	payload := map[string]any{
		"verdict": verdict, "marked": insideGroup, "unmarked": outsideGroup,
	}
	if *asJSON {
		if err := writeCompactJSON(payload); err != nil {
			return err
		}
	} else {
		fmt.Printf("[信息] 分片表内样本: %s\n", strings.Join(inside, ", "))
		fmt.Printf("[信息] 分片表外样本: %s\n", strings.Join(outside, ", "))
		fmt.Printf("[信息] 分片表内按子网出现差异: %d/%d 个域名\n",
			insideGroup.Differentiated, insideGroup.Comparable)
		fmt.Printf("[信息] 分片表外按子网出现差异: %d/%d 个域名\n",
			outsideGroup.Differentiated, outsideGroup.Comparable)
		for label, group := range map[string]forwardGroup{"表内": insideGroup, "表外": outsideGroup} {
			for _, item := range group.Results {
				for _, subnet := range sortedKeysOf(item.ByNet) {
					fmt.Printf("  %s %-22s %-18s %s\n", label, item.Domain, subnet,
						strings.Join(item.ByNet[subnet], " "))
				}
			}
		}
	}
	if verdict != "ok" {
		fmt.Fprintln(os.Stderr,
			"[失败] 分片表外的客户端子网拿不到按位置调度的答案——mosproxy 对未打标地址丢掉了 ECS")
		os.Exit(1)
	}
	if insideGroup.Comparable == 0 && outsideGroup.Comparable == 0 {
		fmt.Fprintln(os.Stderr,
			"[警告] 两组都没有可比较的域名，本轮判据没有回答任何问题（不要当成通过）")
	}
	return nil
}

func sampleSubnets(direct *ipset.Set, rows []ecszone.Row, seed int64) (inside, outside []string) {
	prefixes := direct.Prefixes()
	if len(prefixes) == 0 {
		return nil, nil
	}
	rng := rand.New(rand.NewSource(seed))
	for attempt := 0; attempt < 4000 && (len(inside) < 2 || len(outside) < 2); attempt++ {
		prefix := prefixes[rng.Intn(len(prefixes))]
		r, ok := ipset.PrefixRange(prefix)
		if !ok || r.Hi-r.Lo < 256 {
			continue
		}
		base := (r.Lo + uint32(rng.Int63n(int64(r.Hi-r.Lo)))) &^ 0xff
		if base < r.Lo || base+255 > r.Hi {
			continue
		}
		text := fmt.Sprintf("%s/24", ecszone.FormatAddr(base))
		if ecszone.Marked(rows, base+1) {
			if len(inside) < 2 && !contains(inside, text) {
				inside = append(inside, text)
			}
			continue
		}
		if len(outside) < 2 && !contains(outside, text) {
			outside = append(outside, text)
		}
	}
	return inside, outside
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func probeGroup(server string, domains, subnets []string) forwardGroup {
	group := forwardGroup{Subnets: subnets}
	for _, name := range domains {
		item := subnetAnswers{Domain: name, ByNet: map[string][]string{}}
		for _, subnet := range subnets {
			prefix, err := netip.ParsePrefix(subnet)
			if err != nil {
				continue
			}
			answers, err := dotQuery(server, name, prefix)
			if err != nil || len(answers) == 0 {
				continue
			}
			sort.Strings(answers)
			item.ByNet[subnet] = answers
		}
		if item.comparable() {
			group.Comparable++
			if item.differentiated() {
				group.Differentiated++
			}
		}
		group.Results = append(group.Results, item)
	}
	return group
}

func dotQuery(server, name string, subnet netip.Prefix) ([]string, error) {
	id := uint16(rand.Uint32())
	packet, err := dnswire.BuildQueryWithSubnet(id, name, dnswire.TypeA, subnet)
	if err != nil {
		return nil, err
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", server,
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	framed := make([]byte, 2+len(packet))
	binary.BigEndian.PutUint16(framed, uint16(len(packet)))
	copy(framed[2:], packet)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}
	head := make([]byte, 2)
	if _, err := readFullConn(conn, head); err != nil {
		return nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(head))
	if _, err := readFullConn(conn, body); err != nil {
		return nil, err
	}
	msg, err := dnswire.Unpack(body)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range msg.Answers {
		if addr, ok := rr.A(); ok {
			out = append(out, addr.String())
		}
	}
	return out, nil
}

func readFullConn(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func sortedKeysOf(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
