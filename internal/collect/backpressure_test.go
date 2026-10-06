package collect

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func pruneAll(db *sql.DB, now int64) (int64, error) {
	var total int64
	for {
		deleted, done, err := PruneStep(db, now, pruneBatch)
		total += deleted
		if err != nil || done {
			return total, err
		}
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestAStalledDatabaseNeverStallsTheLogPipe(t *testing.T) {
	db, path := newTestDB(t)
	out := &lockedBuffer{}
	consumer := NewConsumer(path, t.TempDir(), out)
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- consumer.Run(reader) }()

	line := []byte(`{"message":"query log","query":{"name":"qq.com","type":1},"resp":{"rcode":0,"resp_by":"cache"}}` + "\n")
	if _, err := writer.Write(line); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "collector 已就绪") {
		if time.Now().After(deadline) {
			t.Fatalf("collector 没有就绪: %q", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	ctx := context.Background()
	lock, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lock.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}

	written := make(chan error, 1)
	go func() {
		var err error
		for i := 0; i < 3*lineBuffer && err == nil; i++ {
			_, err = writer.Write(line)
		}
		written <- err
	}()
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("数据库被锁住时 mosproxy 往管道写日志被卡住了——" +
			"它的日志写在应答之前、还带着一把全局锁，管道一满，所有查询都停在写日志上，" +
			"统计这条旁路就把 DNS 拖停了；读管道的一端必须宁可丢行也不阻塞")
	}

	if _, err := lock.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	lock.Close()
	writer.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if consumer.dropped.Load() == 0 {
		t.Fatal("写了 3 倍缓冲的行数而数据库被锁，却一行都没丢——这个用例没有测到背压")
	}
	if !strings.Contains(out.String(), "DNS 应答不受影响") {
		t.Errorf("丢了行却没有告警，统计数字会悄悄偏小: %q", out.String())
	}
	var dropped int64
	if err := db.QueryRow("SELECT value FROM collector_state WHERE key = ?", stateDroppedLines).Scan(&dropped); err != nil {
		t.Fatal(err)
	}
	if dropped != consumer.dropped.Load() {
		t.Errorf("库里记的丢弃数 %d，实际 %d；面板靠它提示「统计在采样」", dropped, consumer.dropped.Load())
	}
}

func TestPruneDeletesInBoundedBatches(t *testing.T) {
	db, _ := newTestDB(t)
	now := int64(10_000_000)
	stale := now - (eventRetentionDays+1)*86400
	var events []Event
	for i := 0; i < 12; i++ {
		events = append(events, Event{TS: stale, Domain: "old.example", Route: "cn"})
	}
	events = append(events, Event{TS: now, Domain: "fresh.example", Route: "cn"})
	if err := RecordEvents(db, events); err != nil {
		t.Fatal(err)
	}

	var steps []int64
	for {
		deleted, done, err := PruneStep(db, now, 5)
		if err != nil {
			t.Fatal(err)
		}
		steps = append(steps, deleted)
		if done {
			break
		}
		if len(steps) > 10 {
			t.Fatal("清理停不下来")
		}
	}
	if len(steps) != 3 || steps[0] != 5 || steps[1] != 5 || steps[2] != 2 {
		t.Fatalf("每批删除 %v，期望 [5 5 2]——一条 DELETE 删完积压会让写锁一次占住好几秒", steps)
	}
	var domains int64
	if err := db.QueryRow("SELECT COUNT(*) FROM domains").Scan(&domains); err != nil {
		t.Fatal(err)
	}
	if domains != 1 {
		t.Fatalf("domains 剩 %d 行，期望 1：分批之后 domains 仍要和事件表同一个窗口", domains)
	}
}

func TestRowCapKeepsTheNewestIDsWithoutCountingTheTable(t *testing.T) {
	db, _ := newTestDB(t)
	now := int64(10_000_000)
	if err := RecordEvents(db, []Event{
		{TS: now, Domain: "a.example", Route: "cache"},
		{TS: now, Domain: "b.example", Route: "cache"},
		{TS: now, Domain: "c.example", Route: "cache"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		"INSERT INTO query_events(id, ts, domain, qtype, rcode) VALUES (?, ?, 'newest.example', 1, 0)",
		eventMaxRows+2, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pruneAll(db, now); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query("SELECT id FROM query_events ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var kept []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		kept = append(kept, id)
	}
	if len(kept) != 2 || kept[0] != 3 || kept[1] != eventMaxRows+2 {
		t.Fatalf("保留的 id = %v，期望只留最新 %d 个 id 范围内的 [3 %d]", kept, eventMaxRows, eventMaxRows+2)
	}
}
