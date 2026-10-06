package collect

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func queryLogLine(name string) string {
	return fmt.Sprintf(`{"message":"query log","time":1700000000123,`+
		`"query":{"name":%q,"type":1},"meta":{"server":"doh-in"},`+
		`"resp":{"rcode":0,"resp_by":"local-unbound"},"elapsed":9.5}`, name)
}

func TestOneOversizedLogLineDoesNotStopTheCollector(t *testing.T) {
	path := filepath.Join(t.TempDir(), "collector.db")
	input := strings.Join([]string{
		queryLogLine("before.example"),
		`{"message":"` + strings.Repeat("x", 2*maxLineBytes) + `"}`,
		queryLogLine("after.example"),
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := NewConsumer(path, t.TempDir(), &out).Run(strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	db, err := OpenDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var after int
	if err := db.QueryRow("SELECT COUNT(*) FROM query_events WHERE domain = 'after.example'").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != 1 {
		t.Fatalf("超长行之后的查询没有落库——bufio.Scanner 遇到 ErrTooLong 就永久停下，" +
			"collector 随后返回 nil，统计从此静默中断，外层还会卡在 Wait 上不再读管道")
	}
	if !strings.Contains(out.String(), "跳过了超长日志行") {
		t.Errorf("跳过了超长行却没有任何告警：%q", out.String())
	}
}

func TestForEachLineHandlesLinesLongerThanTheReadBuffer(t *testing.T) {
	long := strings.Repeat("y", 200*1024)
	var got []string
	skipped := 0
	err := forEachLine(strings.NewReader("a\n"+long+"\n"+strings.Repeat("z", 300)+"\nlast-without-newline"), 256*1024,
		func(line string) { got = append(got, line) }, func() { skipped++ })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got[0] != "a" || got[1] != long || len(got[2]) != 300 || got[3] != "last-without-newline" {
		t.Fatalf("按行切分出错：%d 行，首行 %q，第二行长度 %d", len(got), got[0], len(got[1]))
	}
	if skipped != 0 {
		t.Fatalf("没有超限的行却报告了 %d 次跳过", skipped)
	}
}
