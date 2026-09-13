package polluted

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/dnswire"
	"github.com/dns-stack/dns-stack/internal/resolve"
)

var (
	DefaultProbeServers = []string{
		"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "4.2.2.2", "77.88.8.8",
	}
	DefaultProbeDomains = []string{
		"facebook.com", "twitter.com", "youtube.com", "instagram.com",
		"telegram.org", "whatsapp.com", "tumblr.com", "blogspot.com",
	}
)

const (
	DefaultRounds       = 3
	DefaultProbeTimeout = 2 * time.Second
	DefaultTrustedPort  = 5335
	probeQueryPort      = 53
)

type CollectOptions struct {
	StateDir        string
	TrustedServer   string
	TrustedPort     int
	ProbeServers    []string
	ProbeDomains    []string
	Rounds          int
	Timeout         time.Duration
	MaxAgeDays      int
	MinObservations int
	Out             io.Writer
	Now             func() time.Time
	Rand            *rand.Rand
}

type CollectResult struct {
	RawCaptured int
	RawUnique   int
	Observed    int
	Added       int
	Total       int
	NoSample    bool
}

func (o *CollectOptions) fill() {
	if o.TrustedServer == "" {
		o.TrustedServer = "10.100.0.3"
	}
	if o.TrustedPort <= 0 {
		o.TrustedPort = DefaultTrustedPort
	}
	if len(o.ProbeServers) == 0 {
		o.ProbeServers = DefaultProbeServers
	}
	if len(o.ProbeDomains) == 0 {
		o.ProbeDomains = DefaultProbeDomains
	}
	if o.Rounds <= 0 {
		o.Rounds = DefaultRounds
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultProbeTimeout
	}
	if o.MaxAgeDays <= 0 {
		o.MaxAgeDays = 30
	}
	if o.MinObservations <= 0 {
		o.MinObservations = 2
	}
	if o.Out == nil {
		o.Out = io.Discard
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Rand == nil {
		o.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
}

func Collect(ctx context.Context, opt CollectOptions) (CollectResult, error) {
	opt.fill()
	if opt.StateDir == "" {
		return CollectResult{}, fmt.Errorf("状态目录未配置")
	}
	syncDir := filepath.Join(opt.StateDir, "sync-state")
	if err := os.MkdirAll(syncDir, 0o755); err != nil {
		return CollectResult{}, err
	}
	work, err := os.MkdirTemp("", "dns-stack-polluted-*")
	if err != nil {
		return CollectResult{}, err
	}
	defer os.RemoveAll(work)

	trusted, err := resolve.NewClient(opt.TrustedServer, opt.TrustedPort, opt.Timeout)
	if err != nil {
		return CollectResult{}, fmt.Errorf("可信解析器地址无效: %w", err)
	}
	logf := func(format string, args ...any) { fmt.Fprintf(opt.Out, format+"\n", args...) }
	logf("[信息] 开始探测(%d 个境外 DNS × %d 个域名 × %d 轮)...",
		len(opt.ProbeServers), len(opt.ProbeDomains), opt.Rounds)

	var captured []netip.Addr
	for round := 1; round <= opt.Rounds; round++ {
		prefix := fmt.Sprintf("zz%d%d", opt.Rand.Int31n(32768), opt.Rand.Int31n(32768))
		for _, server := range opt.ProbeServers {
			probe, err := resolve.NewClient(server, probeQueryPort, opt.Timeout)
			if err != nil {
				continue
			}
			for _, domain := range opt.ProbeDomains {
				if ctx.Err() != nil {
					return CollectResult{}, ctx.Err()
				}
				fqdn := prefix + "." + domain
				if !confirmedNXDomain(ctx, trusted, fqdn) {
					continue
				}
				for _, qtype := range []uint16{dnswire.TypeA, dnswire.TypeAAAA} {
					answer := probe.Query(ctx, fqdn, qtype)
					if answer.Status != resolve.StatusOK {
						continue
					}
					v4, v6 := resolve.Addresses(answer)
					captured = append(captured, v4...)
					captured = append(captured, v6...)
				}
			}
		}
		logf("[信息] 第 %d/%d 轮完成，累计捕获 %d 条应答", round, opt.Rounds, len(captured))
	}

	res := CollectResult{RawCaptured: len(captured)}
	if len(captured) == 0 {
		logf("[警告] 未捕获到任何伪造应答。可能当前网络环境不存在 DNS 投毒，或探测被完全丢弃。")
		logf("[警告] 本轮不增加地址；已有证据仅按过期时间维护。")
		res.NoSample = true
	}

	rawPath := filepath.Join(work, "raw.txt")
	var raw strings.Builder
	for _, addr := range captured {
		raw.WriteString(addr.String())
		raw.WriteByte('\n')
	}
	if err := os.WriteFile(rawPath, []byte(raw.String()), 0o600); err != nil {
		return res, err
	}

	outFile := filepath.Join(opt.StateDir, "polluted-ip.txt")
	evidenceFile := filepath.Join(syncDir, "polluted-ip-evidence.json")
	activeOut := filepath.Join(work, "uniq.txt")
	evidenceOut := filepath.Join(work, "evidence.json")
	cidrOut := filepath.Join(work, "cidr.txt")

	runRes, err := Run(Options{
		RawPath:         rawPath,
		EvidencePath:    evidenceFile,
		OldOutputPath:   outFile,
		ActiveOutPath:   activeOut,
		EvidenceOutPath: evidenceOut,
		CIDROutPath:     cidrOut,
		MaxAgeDays:      opt.MaxAgeDays,
		MinObservations: opt.MinObservations,
		Now:             opt.Now,
	})
	if err != nil {
		return res, err
	}
	res.Observed, res.Added, res.Total, res.RawUnique =
		runRes.Observed, runRes.Added, runRes.Total, runRes.RawUnique
	logf("[信息] %d 个候选中有 %d 个达到至少 %d 次独立观测的门槛",
		res.RawUnique, res.Observed, opt.MinObservations)

	active, err := os.ReadFile(activeOut)
	if err != nil {
		return res, err
	}
	header := strings.Join([]string{
		"# GFW DNS 污染 IP 列表",
		"# 由 dns-stack collect-polluted 自动采集，每行一个 IPv4 或 IPv6 地址。",
		"#",
		"# 采集方法：向境外公共 DNS 查询随机生成的、必然不存在的子域",
		"#           (如 zz123456.facebook.com)。真实权威 DNS 只会回 NXDOMAIN，",
		"#           凡是还能拿到 A 记录的，该应答必为伪造 —— 不依赖延迟阈值。",
		"#",
		"# 污染池会轮换，本文件是历次采集的累积并集，条目只增不减。",
		"# 最后更新: " + opt.Now().Format("2006-01-02 15:04:05 -0700"),
		fmt.Sprintf("# 本次新增: %d    累计: %d", res.Added, res.Total),
		"",
		"",
	}, "\n")
	if err := replaceFile(outFile, append([]byte(header), active...)); err != nil {
		return res, err
	}
	if err := moveFile(evidenceOut, evidenceFile); err != nil {
		return res, err
	}
	if err := moveFile(cidrOut, filepath.Join(syncDir, "polluted-ip-cidr.local.txt")); err != nil {
		return res, err
	}

	status := "polluted_ok total=" + strconv.Itoa(res.Total) + " added=" + strconv.Itoa(res.Added)
	if res.NoSample {
		status = "polluted_no_sample total=" + strconv.Itoa(res.Total)
	}
	appendHistory(filepath.Join(syncDir, "history.log"), opt.Now(), status)
	logf("[成功] 污染 IPv4/IPv6 本地证据已更新：本次新增 %d 个，累计 %d 个", res.Added, res.Total)
	return res, nil
}

func confirmedNXDomain(ctx context.Context, client *resolve.Client, fqdn string) bool {
	return client.Query(ctx, fqdn, dnswire.TypeA).Status == resolve.StatusNXDomain
}

func replaceFile(path string, body []byte) error {
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

func moveFile(src, dst string) error {
	body, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return replaceFile(dst, body)
}

func appendHistory(path string, now time.Time, line string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", now.UTC().Format("2006-01-02T15:04:05Z"), line)
}
