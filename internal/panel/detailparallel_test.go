package panel

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDomainDetailProbesInParallel(t *testing.T) {
	var inFlight, peak atomic.Int32
	fakeHelper(t, func(request map[string]any) map[string]any {
		if request["op"] != "dns_test" {
			return map[string]any{"ok": true, "data": map[string]any{"returncode": 0, "stdout": ""}}
		}
		now := inFlight.Add(1)
		for {
			old := peak.Load()
			if now <= old || peak.CompareAndSwap(old, now) {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
		inFlight.Add(-1)
		args, _ := request["args"].(map[string]any)
		name, _ := args["domain"].(string)
		qtype, _ := args["qtype"].(string)
		answer := ""
		switch {
		case qtype == "NS":
			for i := 1; i <= 6; i++ {
				answer += fmt.Sprintf("%s.\t60\tIN\tNS\tns%d.%s.\n", name, i, name)
			}
		case qtype == "A" && strings.HasPrefix(name, "ns"):
			answer = fmt.Sprintf("%s.\t60\tIN\tA\t8.8.8.%d\n", name, name[2]-'0')
		}
		stdout := ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; ANSWER SECTION:\n" + answer + "\n;; Query time: 1 msec\n"
		return map[string]any{"ok": true, "data": map[string]any{"returncode": 0, "stdout": stdout}}
	})
	server := newOpenServer(t)
	request := httptest.NewRequest("GET", "/api/domain/www.example.com?live=true", nil)
	request.RemoteAddr = "127.0.0.1:1000"
	request.Host = "127.0.0.1:8080"
	response := httptest.NewRecorder()
	start := time.Now()
	server.Handler().ServeHTTP(response, request)
	elapsed := time.Since(start)
	checkedEqual(t, "详情 200", response.Code, 200)

	body := response.Body.String()
	for i := 1; i <= 6; i++ {
		if !strings.Contains(body, fmt.Sprintf("ns%d.example.com", i)) {
			t.Fatalf("权威 ns%d 不见了: %s", i, body)
		}
	}
	if !strings.Contains(body, "ns1.example.com") || strings.Index(body, "ns1.example.com") > strings.Index(body, "ns6.example.com") {
		t.Error("权威顺序应保持 NS 记录的顺序")
	}
	if got := peak.Load(); got < 7 {
		t.Errorf("NS 查询应和实时解析同时进行，最多只有 %d 个查询在途", got)
	}
	if elapsed > 200*time.Millisecond {
		t.Errorf("每个查询 40ms，并行后应在 ~80ms 完成（逐个查是 ~320ms），实际 %v", elapsed)
	}
}
