package panel

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/dns-stack/dns-stack/internal/collect"
)

var goStringConcat = regexp.MustCompile(`"\s*\+\s*\n?\s*"`)

var timeWindowedEventQuery = regexp.MustCompile(`"(SELECT [^"]*FROM query_events[^"]*ts >= \?[^"]*)"`)

func panelTimeWindowedQueries(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range timeWindowedEventQuery.FindAllStringSubmatch(goStringConcat.ReplaceAllString(string(body), ""), -1) {
			out = append(out, match[1])
		}
	}
	return out
}

func seedProductionShapedEvents(t *testing.T) *sql.DB {
	t.Helper()
	db, err := collect.OpenDB(filepath.Join(t.TempDir(), "collector.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	insert, err := tx.Prepare("INSERT INTO query_events(ts,domain,qtype,rcode,route,exit_path) VALUES (?,?,1,?,?,?)")
	if err != nil {
		t.Fatal(err)
	}
	const rows, start = 40000, int64(1_790_000_000 - 7*86400)
	for i := 0; i < rows; i++ {
		rcode := 0
		if i%23 == 0 {
			rcode = 2
		}
		if _, err := insert.Exec(start+int64(i)*(7*86400)/rows, fmt.Sprintf("host%d.example%d.com", i%900, i%300),
			rcode, []string{"cn", "foreign", "cache", "reject"}[i%4], []string{"direct", "tunnel"}[i%2]); err != nil {
			t.Fatal(err)
		}
	}
	if err := insert.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestTimeWindowedQueriesDoNotWalkEveryRowThroughADomainIndex(t *testing.T) {
	queries := panelTimeWindowedQueries(t)
	if len(queries) < 5 {
		t.Fatalf("只从面板源码里抽到 %d 条按时间窗口查 query_events 的 SQL，抽取规则已经失效，下面的检查会空转", len(queries))
	}
	db := seedProductionShapedEvents(t)
	for _, query := range queries {
		args := make([]any, strings.Count(query, "?"))
		for i := range args {
			args[i] = int64(1_790_000_000 - 86400)
		}
		rows, err := db.Query("EXPLAIN QUERY PLAN "+query, args...)
		if err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		var plan []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			plan = append(plan, detail)
		}
		rows.Close()
		joined := strings.Join(plan, " | ")
		if strings.Contains(joined, "SCAN query_events USING INDEX") {
			t.Errorf("%s\n  计划: %s\n只看一个时间窗口，却为了省一次排序把整张表按索引顺序走了一遍、每行再回表。"+
				"生产快照上这类计划让 /api/collected 从 30ms 退回 689ms；对高基数列分组或去重时写成 +domain，"+
				"让它不能借索引顺序，优化器就会改走 ts 索引", query, joined)
		}
	}
}
