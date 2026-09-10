package collect

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	flushInterval      = 2 * time.Second
	checkpointInterval = 60 * time.Second
	pruneInterval      = time.Hour
	maxBatch           = 5000
	reconnectAfter     = 3

	nonASCIIReportEvery = 1000
)

func ClassifyRoute(respBy string) string {
	switch {
	case respBy == "":
		return "reject"
	case respBy == "cache":
		return "cache"
	case strings.HasPrefix(respBy, "local"):
		return "cn"
	case strings.HasPrefix(respBy, "foreign"):
		return "foreign"
	}
	return "unknown"
}

func ClassifyExitPath(zones *ZoneSet, domain, route string) string {
	switch route {
	case "cache":
		return "cache"
	case "foreign":
		return "hongkong"
	}
	if route != "cn" {
		return route
	}
	if zones.Covers(domain) {
		return "direct"
	}
	return "tunnel"
}

type ZoneSet struct {
	path  string
	mu    sync.Mutex
	mtime time.Time
	zones map[string]struct{}
}

func NewZoneSet(path string) *ZoneSet {
	return &ZoneSet{path: path}
}

func (z *ZoneSet) refresh() {
	info, err := os.Stat(z.path)
	if err != nil {
		z.zones, z.mtime = nil, time.Time{}
		return
	}
	if info.ModTime().Equal(z.mtime) {
		return
	}
	raw, err := os.ReadFile(z.path)
	if err != nil {
		return
	}
	zones := make(map[string]struct{})
	for _, line := range strings.Split(string(raw), "\n") {
		value := strings.ToLower(strings.TrimSpace(line))
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		zones[value] = struct{}{}
	}
	z.zones, z.mtime = zones, info.ModTime()
}

func (z *ZoneSet) Covers(domain string) bool {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.refresh()
	if len(z.zones) == 0 {
		return false
	}
	labels := strings.Split(domain, ".")
	for index := range labels {
		if _, ok := z.zones[strings.Join(labels[index:], ".")]; ok {
			return true
		}
	}
	return false
}

type Consumer struct {
	dbPath string
	zones  *ZoneSet
	out    io.Writer
	now    func() time.Time

	db      *sql.DB
	pending []Event

	consecutiveFailures int
	failureReported     bool
	nonASCIIDropped     int
}

func NewConsumer(dbPath, stateDir string, out io.Writer) *Consumer {
	if stateDir == "" {
		stateDir = DefaultStateDir
	}
	return &Consumer{
		dbPath: dbPath,
		zones:  NewZoneSet(stateDir + "/chnroute/cn-zones-matched.txt"),
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
	route := ClassifyRoute(respBy)
	serverTag, _ := meta["server"].(string)
	prefetch := int64(0)
	if flag, ok := query["prefetch"].(bool); ok && flag {
		prefetch = 1
	}
	c.pending = append(c.pending, Event{
		TS: ts, Domain: normalized,
		QType: numberOf(query["type"]), RCode: numberOf(resp["rcode"]),
		RespBy: respBy, Route: route,
		ExitPath:  ClassifyExitPath(c.zones, normalized, route),
		ServerTag: serverTag, Prefetch: prefetch, ElapsedMS: elapsed,
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
	db, err := OpenDB(c.dbPath)
	if err != nil {
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

	lines := make(chan string, maxBatch)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(input)

		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()

	lastFlush, lastCheckpoint, lastPrune := c.now(), c.now(), c.now()
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				c.Flush()
				return nil
			}
			if text := strings.TrimSpace(line); text != "" {
				c.HandleLine(text)
			}
		case <-ticker.C:
		}
		now := c.now()
		if len(c.pending) >= maxBatch || now.Sub(lastFlush) >= flushInterval {
			c.Flush()
			lastFlush = now
		}
		if now.Sub(lastCheckpoint) >= checkpointInterval {
			_ = Checkpoint(c.db)
			lastCheckpoint = now
		}
		if now.Sub(lastPrune) >= pruneInterval {
			_, _ = PruneEvents(c.db, now.Unix())
			lastPrune = now
		}
	}
}
