package panel

import (
	"encoding/json"
	"strings"
	"testing"
)

const digAnswer = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n" +
	";; ANSWER SECTION:\n%s.\t60\tIN\tA\t8.8.4.4\n\n;; Query time: 3 msec\n"

func TestDomainListDoesNotWaitForResolution(t *testing.T) {
	calls := fakeHelper(t, func(request map[string]any) map[string]any {
		args, _ := request["args"].(map[string]any)
		name, _ := args["domain"].(string)
		return map[string]any{"ok": true, "data": map[string]any{"returncode": 0,
			"stdout": strings.Replace(digAnswer, "%s", name, 1)}}
	})
	server := newExportServer(t)

	list := exportRequest(t, server, "/api/domains?page=1&size=50")
	checkedEqual(t, "列表 200", list.Code, 200)
	if n := len(calls()); n != 0 {
		t.Fatalf("域名列表不该再同步解析，helper 被调了 %d 次", n)
	}
	var body struct {
		Pending []string `json:"nodes_pending"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Pending) != 2 {
		t.Fatalf("两个域名都该待解析: %v", body.Pending)
	}

	nodes := exportRequest(t, server, "/api/domains/nodes?names="+strings.Join(body.Pending, ",")+",bad%20name")
	checkedEqual(t, "节点 200", nodes.Code, 200)
	var got struct {
		Nodes map[string]map[string]any `json:"nodes"`
	}
	if err := json.Unmarshal(nodes.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Nodes) != 2 || got.Nodes["www.example.com"]["ip"] != "8.8.4.4" {
		t.Fatalf("节点结果不对（非法名字应被丢弃）: %v", got.Nodes)
	}
	resolved := len(calls())

	again := exportRequest(t, server, "/api/domains?page=1&size=50")
	if !strings.Contains(again.Body.String(), "8.8.4.4") || strings.Contains(again.Body.String(), `"nodes_pending":["`) {
		t.Fatalf("第二次列表应直接带上缓存的节点: %s", again.Body.String())
	}
	exportRequest(t, server, "/api/domains/nodes?names=www.example.com")
	if len(calls()) != resolved {
		t.Fatal("缓存命中时不该再调 helper")
	}
}

func TestSlowDomainListSkipsResolution(t *testing.T) {
	calls := fakeHelper(t, func(map[string]any) map[string]any { return map[string]any{"ok": true} })
	server := newExportServer(t)
	exportRequest(t, server, "/api/domains?metric=slow")
	if n := len(calls()); n != 0 {
		t.Fatalf("耗时排行不显示节点，不该解析，helper 被调了 %d 次", n)
	}
}
