package panel

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	for _, payload := range []string{`{"domain":"1.2.3.4"}`, `{"domain":""}`, `{"domain":"example..com"}`, `{"domain":"example.com","subnet":"192.0.2.0/24"}`, `{"domain":"example.com","subnet":"1.2.3.4/24"}`} {
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

func TestStaleListsDoNotProveDomesticRouting(t *testing.T) {
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
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	var out map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	checkedEqual(t, "domain normalization", out["domain"], "www.foreign.com")
	checkedEqual(t, "foreign authority is not domestic evidence", out["routing"].(map[string]any)["direction"], "adaptive")
}
