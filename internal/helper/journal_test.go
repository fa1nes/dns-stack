package helper

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestJournalMergesUnitsInOneCall(t *testing.T) {
	h := newTestHelper(t)
	var seen [][]string
	h.onRun = func(argv []string) { seen = append(seen, argv) }
	out := h.opLogs(map[string]any{"units": []any{"mosproxy", "unbound"}, "lines": float64(5000), "after_cursor": "s=ab12;i=3f"})
	if ok, _ := out["ok"].(bool); !ok || len(seen) != 1 {
		t.Fatalf("应当只跑一次 journalctl: %v %v", out, seen)
	}
	argv := strings.Join(seen[0], " ")
	for _, want := range []string{"-u mosproxy.service", "-u unbound.service", "-n 2000", "--output json", "--after-cursor s=ab12;i=3f"} {
		if !strings.Contains(argv, want) {
			t.Errorf("命令行缺 %q: %s", want, argv)
		}
	}
}

func TestJournalRejectsUnknownUnitAndBadCursor(t *testing.T) {
	h := newTestHelper(t)
	h.onRun = func(argv []string) { t.Fatalf("不该执行: %v", argv) }
	for _, args := range []map[string]any{
		{"units": []any{"mosproxy", "sshd"}},
		{"units": []any{}},
		{"units": []any{"mosproxy"}, "after_cursor": "s=1 --since today"},
	} {
		if ok, _ := h.opLogs(args)["ok"].(bool); ok {
			t.Errorf("应当拒绝 %v", args)
		}
	}
}

func TestSanitizeJournalKeepsEachLineValidJSON(t *testing.T) {
	h := newTestHelper(t)
	input := strings.Join([]string{
		`{"MESSAGE":"login password=hunter2, from 203.0.113.9","PRIORITY":"6","__CURSOR":"s=1"}`,
		`{"MESSAGE":[104,105,255],"PRIORITY":"6"}`,
		`{"MESSAGE":"GET /qX7pLm2v9Kd4Rt8w/dns-query","PRIORITY":"6"}`,
		`truncated","PRIORITY":"6"}`,
	}, "\n")
	lines := strings.Split(strings.TrimSpace(h.sanitizeJournal(input)), "\n")
	if len(lines) != 3 {
		t.Fatalf("截断的首行应被丢弃，其余保留: %q", lines)
	}
	var messages []string
	for _, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("脱敏后不是合法 JSON: %s", line)
		}
		messages = append(messages, rec["MESSAGE"].(string))
	}
	for _, leak := range []string{"hunter2", "203.0.113.9", "qX7pLm2v9Kd4Rt8w"} {
		if slices.ContainsFunc(messages, func(m string) bool { return strings.Contains(m, leak) }) {
			t.Errorf("没脱敏 %q: %q", leak, messages)
		}
	}
	if !strings.HasPrefix(messages[1], "hi") {
		t.Errorf("字节数组形式的 MESSAGE 应当还原成文本: %q", messages[1])
	}
}
