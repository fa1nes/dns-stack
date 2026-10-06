package collect

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

const (
	flushInterval      = 2 * time.Second
	checkpointInterval = 60 * time.Second
	pruneInterval      = time.Hour
	dropReportInterval = time.Minute
	maxBatch           = 5000
	lineBuffer         = maxBatch
	reconnectAfter     = 3

	nonASCIIReportEvery = 1000
)

func ClassifyRoute(respBy string, rcode int64) string {
	switch {
	case respBy == "" && (rcode == rcodeNXDomain || rcode == rcodeRefused):
		return "reject"
	case respBy == "":
		return "failed"
	case respBy == "cache":
		return "cache"
	case strings.HasPrefix(respBy, "local"):
		return "cn"
	case strings.HasPrefix(respBy, "foreign"):
		return "foreign"
	}
	return "unknown"
}

const (
	KindBlocked   = "blocked"
	KindRefused   = "refused"
	KindCache     = "cache"
	KindForward   = "forward"
	KindRecursive = "recursive"
	KindUnknown   = "unknown"

	rcodeNXDomain = 3
	rcodeRefused  = 5

	subnetKeepBitsV4 = 24
	subnetKeepBitsV6 = 48
)

func KindLabel(kind string) string {
	switch kind {
	case KindBlocked:
		return "域名黑名单"
	case KindRefused:
		return "限流拒绝"
	case KindCache:
		return "缓存"
	case KindForward:
		return "转发"
	case KindRecursive:
		return "递归"
	default:
		return "未知"
	}
}

func ClassifyKind(respBy string, rcode int64) string {
	switch {
	case respBy == "" && rcode == rcodeNXDomain:
		return KindBlocked
	case respBy == "" && rcode == rcodeRefused:
		return KindRefused
	case respBy == "":
		return KindUnknown
	case respBy == "cache":
		return KindCache
	case strings.HasPrefix(respBy, "foreign"):
		return KindForward
	case strings.HasPrefix(respBy, "local"):
		return KindRecursive
	}
	return KindUnknown
}

func CoarseSubnet(value string) string {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil {
		addr, addrErr := netip.ParseAddr(strings.TrimSpace(value))
		if addrErr != nil {
			return ""
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	keep := subnetKeepBitsV6
	if prefix.Addr().Is4() {
		keep = subnetKeepBitsV4
	}
	if prefix.Bits() > keep {
		prefix = netip.PrefixFrom(prefix.Addr(), keep)
	}
	return prefix.Masked().String()
}

func ClassifyExitPath(route string) string {
	switch route {
	case "foreign":
		return "hongkong"
	case "cache":
		return "cache"
	case "cn":
		return "recursive"
	}
	return route
}

type Consumer struct {
	dbPath string
	out    io.Writer
	now    func() time.Time

	db      *sql.DB
	pending []Event

	consecutiveFailures int
	failureReported     bool
	nonASCIIDropped     int
	malformedDropped    int
	oversized           atomic.Int64
	oversizedReported   int64
	dropped             atomic.Int64
	droppedReported     int64
	droppedReportedAt   time.Time
	readErr             error
}

func NewConsumer(dbPath, stateDir string, out io.Writer) *Consumer {
	if stateDir == "" {
		stateDir = DefaultStateDir
	}
	return &Consumer{
		dbPath: dbPath,
		out:    out,
		now:    time.Now,
	}
}

func (c *Consumer) log(level, message string, extra map[string]any) {
	payload := map[string]any{"level": level, "module": "collector", "message": message}
	for key, value := range extra {
		payload[key] = value
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return
	}
	fmt.Fprintln(c.out, string(encoded))
}

const maxLineBytes = 1 << 20

func (c *Consumer) reportOversized() {
	if n := c.oversized.Load(); n > c.oversizedReported {
		c.log("warn", "跳过了超长日志行", map[string]any{"count": n - c.oversizedReported, "limit_bytes": maxLineBytes})
		c.oversizedReported = n
	}
}

func forEachLine(input io.Reader, limit int, emit func(string), oversized func()) error {
	reader := bufio.NewReaderSize(input, 64*1024)
	var line []byte
	tooLong := false
	for {
		chunk, isPrefix, err := reader.ReadLine()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if !tooLong {
			if len(line)+len(chunk) > limit {
				tooLong = true
				line = line[:0]
			} else {
				line = append(line, chunk...)
			}
		}
		if isPrefix {
			continue
		}
		if tooLong {
			oversized()
		} else {
			emit(string(line))
		}
		line, tooLong = line[:0], false
	}
}

func (c *Consumer) HandleLine(text string) {
	var obj map[string]any
	if json.Unmarshal([]byte(text), &obj) != nil {
		fmt.Fprintln(c.out, text)
		return
	}
	message, _ := obj["message"].(string)
	if message == "" {
		message, _ = obj["msg"].(string)
	}
	if message != "query log" {
		fmt.Fprintln(c.out, text)
		return
	}

	query, _ := obj["query"].(map[string]any)
	rawName, _ := query["name"].(string)
	if rawName == "" {
		return
	}
	normalized := NormalizeDomain(rawName)
	if normalized == "" {

		if NonASCII(rawName) {
			c.nonASCIIDropped++
			if c.nonASCIIDropped == 1 || c.nonASCIIDropped%nonASCIIReportEvery == 0 {
				c.log("warn", "遇到非 ASCII 查询名，已跳过（本实现不做 IDNA 转换）",
					map[string]any{"dropped": c.nonASCIIDropped})
			}
			return
		}
		c.malformedDropped++
		if c.malformedDropped == 1 || c.malformedDropped%nonASCIIReportEvery == 0 {
			c.log("warn", "遇到不合法的查询名，已跳过", map[string]any{"dropped": c.malformedDropped, "example": rawName})
		}
		return
	}

	resp, _ := obj["resp"].(map[string]any)
	meta, _ := obj["meta"].(map[string]any)
	respBy, _ := resp["resp_by"].(string)

	ts := c.now().Unix()
	if raw, ok := obj["time"].(float64); ok && raw > 1e11 {
		ts = int64(raw / 1000)
	}
	var elapsed *float64
	if raw, ok := obj["elapsed"].(float64); ok {
		value := raw
		elapsed = &value
	}
	rcode := numberOf(resp["rcode"])
	route := ClassifyRoute(respBy, rcode)
	serverTag, _ := meta["server"].(string)
	prefetch := int64(0)
	if flag, ok := query["prefetch"].(bool); ok && flag {
		prefetch = 1
	}
	clientSubnet := ""
	if raw, ok := query["ecs"].(string); ok {
		clientSubnet = CoarseSubnet(raw)
	}
	ecsZone, _ := query["ecs_zone"].(string)
	c.pending = append(c.pending, Event{
		TS: ts, Domain: normalized,
		QType: numberOf(query["type"]), RCode: rcode,
		RespBy: respBy, Route: route,
		ExitPath:  ClassifyExitPath(route),
		ServerTag: serverTag, Prefetch: prefetch, ElapsedMS: elapsed,
		ClientSubnet: clientSubnet, ECSZone: ecsZone,
		Kind: ClassifyKind(respBy, rcode),
	})
}

func numberOf(value any) int64 {
	if number, ok := value.(float64); ok {
		return int64(number)
	}
	return 0
}

func (c *Consumer) Flush() {
	if len(c.pending) == 0 {
		return
	}
	batch := c.pending
	c.pending = nil
	if err := RecordEvents(c.db, batch); err != nil {
		c.consecutiveFailures++
		if !c.failureReported {

			c.log("error", "事件写入失败，本批已丢弃", map[string]any{
				"error": truncate(err.Error(), 300), "batch_size": len(batch),
			})
			c.failureReported = true
		}

		if c.consecutiveFailures >= reconnectAfter {
			_ = c.db.Close()
			db, err := OpenDB(c.dbPath)
			if err != nil {
				c.log("error", "重建数据库连接失败，稍后重试",
					map[string]any{"error": truncate(err.Error(), 200)})
				return
			}
			c.db = db
			c.consecutiveFailures = 0
			c.log("warn", "已重建数据库连接以尝试自愈", nil)
		}
		return
	}
	if c.consecutiveFailures > 0 {
		c.log("warn", "事件写入已恢复",
			map[string]any{"dropped_batches": c.consecutiveFailures})
	}
	c.consecutiveFailures = 0
	c.failureReported = false
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func (c *Consumer) Run(input io.Reader) error {
	lines := make(chan string, lineBuffer)
	go func() {
		defer close(lines)
		c.readErr = forEachLine(input, maxLineBytes, func(line string) {
			select {
			case lines <- line:
			default:
				c.dropped.Add(1)
			}
		}, func() { c.oversized.Add(1) })
	}()

	db, err := OpenDB(c.dbPath)
	if err != nil {
		c.log("error", "数据库打不开，查询统计中断，DNS 照常服务",
			map[string]any{"error": truncate(err.Error(), 300)})
		for range lines {
		}
		return err
	}
	c.db = db
	defer func() {
		c.Flush()
		_ = c.db.Close()
	}()
	journalMode, busyTimeout := EffectivePragmas(db)
	c.log("info", "collector 已就绪", map[string]any{
		"journal_mode": journalMode, "busy_timeout_ms": busyTimeout,
	})
	if !strings.EqualFold(journalMode, "wal") || busyTimeout <= 0 {
		c.log("warn", "SQLite 参数未按预期生效，并发写入可能偶发失败", map[string]any{
			"journal_mode": journalMode, "busy_timeout_ms": busyTimeout,
		})
	}

	started := c.now()
	_ = RecordCollectorState(c.db, map[string]int64{
		stateStartedAt: started.Unix(), stateDroppedLines: 0, stateDroppedAt: 0,
	})

	for !c.pruneStep(started) {
	}
	pruning := false
	lastFlush, lastCheckpoint, lastPrune := started, started, started
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for {
		tick := false
		select {
		case line, ok := <-lines:
			if !ok {
				c.Flush()
				c.reportDropped(c.now(), true)
				c.reportOversized()
				return c.readErr
			}
			if text := strings.TrimSpace(line); text != "" {
				c.HandleLine(text)
			}
		case <-ticker.C:
			tick = true
		}
		c.reportOversized()
		now := c.now()
		if len(c.pending) >= maxBatch || now.Sub(lastFlush) >= flushInterval {
			c.Flush()
			lastFlush = now
		}
		if !tick {
			continue
		}
		c.reportDropped(now, false)
		if now.Sub(lastCheckpoint) >= checkpointInterval {
			_ = Checkpoint(c.db)
			lastCheckpoint = now
		}
		if now.Sub(lastPrune) >= pruneInterval {
			pruning = true
			lastPrune = now
		}
		if pruning {
			pruning = !c.pruneStep(now)
		}
	}
}

func (c *Consumer) pruneStep(now time.Time) bool {
	_, done, err := PruneStep(c.db, now.Unix(), pruneBatch)
	if err != nil {
		c.log("warn", "清理过期记录失败，下个周期重试", map[string]any{"error": truncate(err.Error(), 200)})
		return true
	}
	if done {
		_ = CheckpointTruncate(c.db)
	}
	return done
}

func (c *Consumer) reportDropped(now time.Time, force bool) {
	total := c.dropped.Load()
	if total == c.droppedReported || (!force && now.Sub(c.droppedReportedAt) < dropReportInterval) {
		return
	}
	c.log("warn", "统计写入跟不上，丢弃了一部分查询日志；DNS 应答不受影响", map[string]any{
		"dropped": total - c.droppedReported, "dropped_total": total,
	})
	c.droppedReported, c.droppedReportedAt = total, now
	_ = RecordCollectorState(c.db, map[string]int64{stateDroppedLines: total, stateDroppedAt: now.Unix()})
}
