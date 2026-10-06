package panel

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestGlobalEvidenceBoundaries(t *testing.T) {
	for _, value := range []string{"0.1.2.3", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.1.1", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "::", "::1", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1", "2001::1", "3fff::1"} {
		checkedEqual(t, "reject non-routable "+value, isPublicIP(net.ParseIP(value)), false)
	}
	for _, value := range []string{"1.2.3.4", "8.8.8.8", "2001:4860:4860::8888", "2606:4700:4700::1111"} {
		checkedEqual(t, "accept routable "+value, isPublicIP(net.ParseIP(value)), true)
	}
	for _, status := range []string{"SERVFAIL", "NXDOMAIN", "REFUSED"} {
		parsed := map[string]any{"status": status, "records": []map[string]any{{"type": "A", "value": "1.2.3.4"}}}
		checkedEqual(t, "failure is not evidence "+status, len(parsedGlobalIPs(parsed)), 0)
	}
}

func TestDNSTestRejectsBadInputBeforeHelper(t *testing.T) {
	for _, payload := range []string{`{"domain":"example.com","qtype":"AXFR"}`, `{"domain":""}`, `{"domain":"example..com"}`, `{"domain":"example.com","subnet":"192.0.2.0/24"}`, `{"domain":"example.com","subnet":"1.2.3.4/24"}`} {
		t.Run(payload, func(t *testing.T) {
			calls := fakeHelper(t, func(request map[string]any) map[string]any { return map[string]any{"ok": true} })
			server := New(Config{})
			request := httptest.NewRequest("POST", "/api/dns-test", bytes.NewBufferString(payload))
			response := httptest.NewRecorder()
			server.dnsTest(response, request)
			checkedEqual(t, "reject before querying", map[string]any{"status": response.Code, "calls": len(calls())}, map[string]any{"status": 400, "calls": 0})
		})
	}
}

func TestDNSTestPicksTheRecordTypeFromTheInput(t *testing.T) {
	for input, want := range map[string]string{
		"1.2.3.4":               "4.3.2.1.in-addr.arpa PTR",
		"2001:db8::1":           "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa PTR",
		"_dmarc.example.com":    "_dmarc.example.com TXT",
		"_sip._tcp.example.com": "_sip._tcp.example.com SRV",
		"www.example.com":       "www.example.com A+AAAA",
	} {
		name, types := autoQuery(input, "")
		got := name + " " + strings.Join(types, "+")
		if got != want {
			t.Errorf("%s 自动选成了 %q，期望 %q", input, got, want)
		}
	}
	if name, types := autoQuery("example.com", "MX"); name != "example.com" || len(types) != 1 || types[0] != "MX" {
		t.Errorf("手动指定的类型应当照用，得到 %s %v", name, types)
	}
	for raw, want := range map[string]string{
		"https://SB.sb/thread/1?x=1": "sb.sb",
		"https://sb.sb:8443/x":       "sb.sb",
		"sb.sb:443":                  "sb.sb",
		" Example.COM. ":             "example.com",
		"[2001:db8::1]:53":           "2001:db8::1",
		"2001:db8::1":                "2001:db8::1",
		"http://223.5.5.5/":          "223.5.5.5",
	} {
		if got := testTarget(raw); got != want {
			t.Errorf("从地址栏粘进来的 %q 应当认成 %q，得到 %q", raw, want, got)
		}
	}
}

func TestAuthorityHopsShowTheirRealExit(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "chnroute"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"chnroute/direct4.txt": "1.2.3.0/24\n", "chnroute/cn-authority.txt": "8.8.8.8/32\n", "chnroute/cn-zones-matched.txt": "foreign.com\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	fakeHelper(t, func(request map[string]any) map[string]any {

		args, _ := request["args"].(map[string]any)
		name, _ := args["domain"].(string)
		qtype, _ := args["qtype"].(string)
		answer := ""
		if name == "foreign.com" && qtype == "NS" {
			answer = "foreign.com. 60 IN NS ns.foreign.net.\n"
		}
		if name == "ns.foreign.net" && qtype == "A" {
			answer = "ns.foreign.net. 60 IN A 8.8.8.8\n"
		}
		if name == "www.foreign.com" && qtype == "A" {
			answer = "www.foreign.com. 60 IN A 9.9.9.9\n"
		}
		return map[string]any{"ok": true, "data": map[string]any{"returncode": 0, "stdout": ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; ANSWER SECTION:\n" + answer, "stderr": ""}}
	})
	server := New(Config{DBPath: filepath.Join(root, "absent.db"), StateDir: root, AuthPath: filepath.Join(root, "absent-auth.json")})
	request := httptest.NewRequest("GET", "/api/domain/WWW.Foreign.com.?live=true", nil)
	request.RemoteAddr = "127.0.0.1:1000"
	request.Host = "127.0.0.1:8080"
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	var out map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	checkedEqual(t, "domain normalization", out["domain"], "www.foreign.com")
	routing := out["routing"].(map[string]any)
	hops, _ := routing["authorities"].([]any)
	if len(hops) != 1 || hops[0].(map[string]any)["exit"] != "direct" || routing["path"] != "direct" {
		t.Fatalf("8.8.8.8 在国内权威表里，nft 会让这一跳直连，面板也要照实显示：%v", routing)
	}
	checkedEqual(t, "answer outside direct4", routing["result_in_cn"], false)
}

func TestDNSTestAcceptsAPastedURL(t *testing.T) {
	asked := map[string]bool{}
	var mu sync.Mutex
	fakeHelper(t, func(request map[string]any) map[string]any {
		args, _ := request["args"].(map[string]any)
		name, _ := args["domain"].(string)
		mu.Lock()
		asked[name] = true
		mu.Unlock()
		return map[string]any{"ok": true, "data": map[string]any{"returncode": 0,
			"stdout": ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n", "stderr": ""}}
	})
	root := t.TempDir()
	server := New(Config{DBPath: filepath.Join(root, "absent.db"), StateDir: root, AuthPath: filepath.Join(root, "absent-auth.json")})
	request := httptest.NewRequest("POST", "/api/dns-test", strings.NewReader(`{"domain":"https://SB.sb:8443/thread/1"}`))
	request.RemoteAddr = "127.0.0.1:1000"
	request.Host = "127.0.0.1:8080"
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	var out map[string]any
	_ = json.Unmarshal(response.Body.Bytes(), &out)
	if out["domain"] != "sb.sb" || !asked["sb.sb"] {
		t.Fatalf("从地址栏粘贴的网址应当按 sb.sb 去查，得到 %d %v，问过 %v", response.Code, out["domain"], asked)
	}
}
