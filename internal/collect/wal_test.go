package collect

import (
	"os"
	"testing"
)

func TestCheckpointTruncateShrinksTheWAL(t *testing.T) {
	db, path := newTestDB(t)
	wal := path + "-wal"

	events := make([]Event, 0, 4000)
	for i := 0; i < 4000; i++ {
		events = append(events, Event{TS: int64(1_700_000_000 + i), Domain: "a.example", Route: "cn"})
	}
	if err := RecordEvents(db, events); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(wal)
	if err != nil {
		t.Skipf("这个平台没有走 WAL: %v", err)
	}
	grown := info.Size()
	if grown == 0 {
		t.Skip("WAL 为空，无法验证截断")
	}

	if err := Checkpoint(db); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(wal)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() < grown {
		t.Fatalf("PASSIVE 竟然缩了文件(%d -> %d)——这个测试的前提没了，重新确认 SQLite 行为",
			grown, after.Size())
	}

	if err := CheckpointTruncate(db); err != nil {
		t.Fatal(err)
	}
	final, err := os.Stat(wal)
	if err != nil {
		t.Fatal(err)
	}
	if final.Size() >= grown {
		t.Fatalf("TRUNCATE 之后 WAL 仍是 %d 字节（截断前 %d）——文件没被回收", final.Size(), grown)
	}
}
