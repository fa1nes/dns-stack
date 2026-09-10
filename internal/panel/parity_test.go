package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func checkedEqual(t *testing.T, label string, got, want any) {
	t.Helper()
	normalize := func(value any) any {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var decoded any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	actual, expected := normalize(got), normalize(want)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("%s: got %s; want %s", label, jsonText(actual), jsonText(expected))
	}
	count := 0
	var visit func(any)
	visit = func(value any) {
		switch values := value.(type) {
		case map[string]any:
			for key, old := range values {
				values[key] = map[string]any{"__negative_field__": old}
				if reflect.DeepEqual(actual, expected) {
					t.Fatalf("%s: mutation of %s escaped comparator", label, key)
				}
				values[key] = old
				count++
				visit(old)
			}
		case []any:
			for index, old := range values {
				values[index] = map[string]any{"__negative_item__": old}
				if reflect.DeepEqual(actual, expected) {
					t.Fatalf("%s: mutation of item %d escaped comparator", label, index)
				}
				values[index] = old
				count++
				visit(old)
			}
		}
	}
	visit(actual)
	if count == 0 {
		if reflect.DeepEqual(map[string]any{"__negative_value__": actual}, expected) {
			t.Fatalf("%s: scalar mutation escaped comparator", label)
		}
		count++
	}
	t.Logf("%s: exact parity; rejected %d field mutations", label, count)
}

func jsonText(value any) string { encoded, _ := json.Marshal(value); return string(encoded) }

func listenTestHelper(t *testing.T) (net.Listener, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		return listener, "tcp://" + listener.Addr().String()
	}
	path := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	return listener, path
}

func fakeHelper(t *testing.T, response func(map[string]any) map[string]any) func() []map[string]any {
	t.Helper()
	listener, path := listenTestHelper(t)
	t.Setenv("DNS_STACK_HELPER_SOCK", path)
	var mutex sync.Mutex
	calls := []map[string]any{}
	var workers sync.WaitGroup
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer connection.Close()
				var request map[string]any
				if json.NewDecoder(connection).Decode(&request) != nil {
					return
				}
				mutex.Lock()
				calls = append(calls, request)
				mutex.Unlock()
				_ = json.NewEncoder(connection).Encode(response(request))
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-closed; workers.Wait() })
	return func() []map[string]any {
		mutex.Lock()
		defer mutex.Unlock()
		return append([]map[string]any{}, calls...)
	}
}

func TestProductionPanelParity(t *testing.T) {
	root := os.Getenv("PANEL_PARITY_FIXTURES")
	if root == "" {
		t.Skip("production fixtures require CN parity script")
	}
	encoded, err := os.ReadFile(filepath.Join(root, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name                 string            `json:"name"`
		Role                 string            `json:"role"`
		Path                 string            `json:"path"`
		Method               string            `json:"method"`
		Payload              any               `json:"payload"`
		Auth                 any               `json:"auth"`
		Session              string            `json:"session"`
		Time                 int64             `json:"time"`
		Status               int               `json:"status"`
		Expected             any               `json:"expected"`
		HelperResponse       map[string]any    `json:"helper_response"`
		HelperCalls          []map[string]any  `json:"helper_calls"`
		UnorderedHelperCalls bool              `json:"unordered_helper_calls"`
		Raw                  bool              `json:"raw"`
		Headers              map[string]string `json:"headers"`
		Volatile             []string          `json:"volatile"`
		Remote               string            `json:"remote"`
	}
	if err := json.Unmarshal(encoded, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("empty production parity corpus")
	}

	pristineDB := copyFixtureDB(t, filepath.Join(root, "collector.db"), t.TempDir())
	for _, item := range cases {
		t.Run(item.Name, func(t *testing.T) {
			directory := t.TempDir()

			config := filepath.Join(directory, "config.env")
			auth := filepath.Join(directory, "auth.json")
			configContent := "ROLE=" + item.Role + "\n" +
				"GITHUB_RAW_BASE=https://raw.githubusercontent.com/owner/repo/main\n" +
				"GITHUB_MIRROR_1=https://mirror-1.example.com/owner/repo/main\n" +
				"GITHUB_MIRROR_2=\n" +
				"GITHUB_REPOSITORY=owner/repo\n" +
				"GITHUB_BRANCH=main\n"
			if err := os.WriteFile(config, []byte(configContent), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(auth, []byte(jsonText(item.Auth)), 0600); err != nil {
				t.Fatal(err)
			}
			dbPath := filepath.Join(root, "collector.db")
			if item.Name == "audit" {

				dbPath = pristineDB
			}
			server := New(Config{DBPath: dbPath, StateDir: filepath.Join(root, "state"), ConfigPath: config, AuthPath: auth, TOTPStepPath: filepath.Join(directory, "step")})
			server.clock = func() time.Time { return time.Unix(item.Time, 0) }
			calls := fakeHelper(t, func(request map[string]any) map[string]any { return item.HelperResponse })
			request := httptest.NewRequest(item.Method, item.Path, bytes.NewBufferString(jsonText(item.Payload)))

			request.RemoteAddr = item.Remote
			if request.RemoteAddr == "" {
				request.RemoteAddr = "198.51.100.1:12345"
			}
			request.AddCookie(&http.Cookie{Name: "dns_stack_session", Value: item.Session})
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if item.Raw {

				expected, ok := item.Expected.(string)
				if !ok {
					t.Fatalf("%s: raw case expected must be a string", item.Name)
				}
				checkedEqual(t, "raw response", map[string]any{"status": response.Code, "body": response.Body.String()}, map[string]any{"status": item.Status, "body": expected})
				for key, value := range item.Headers {
					checkedEqual(t, "header "+key, response.Header().Get(key), value)
				}
			} else {
				var body any
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatal(err, response.Body.String())
				}
				got := map[string]any{"status": response.Code, "body": body}
				want := map[string]any{"status": item.Status, "body": item.Expected}

				for _, path := range item.Volatile {
					structuralize(t, got, path)
					structuralize(t, want, path)
				}
				checkedEqual(t, "response", got, want)
			}
			actualCalls := calls()
			expectedCalls := item.HelperCalls
			if item.UnorderedHelperCalls {

				sortByJSON(actualCalls)
				sortByJSON(expectedCalls)
			}
			checkedEqual(t, "helper request sequence", actualCalls, expectedCalls)
		})
	}
}

func copyFixtureDB(t *testing.T, source, directory string) string {
	t.Helper()
	target := filepath.Join(directory, "collector.db")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, err := os.ReadFile(source + suffix)
		if err != nil {
			if suffix == "" {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(target+suffix, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return target
}

func structuralize(t *testing.T, root map[string]any, path string) {
	t.Helper()
	parts := strings.Split(path, ".")
	cursor := any(root)
	for _, key := range parts[:len(parts)-1] {
		node, ok := cursor.(map[string]any)
		if !ok {
			return
		}
		cursor = node[key]
	}
	node, ok := cursor.(map[string]any)
	if !ok {
		return
	}
	last := parts[len(parts)-1]
	if _, exists := node[last]; !exists {

		return
	}
	node[last] = shapeOf(node[last])
}

func shapeOf(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for key, item := range typed {
			out[key] = shapeOf(item)
		}
		return out
	case []any:
		return map[string]any{"__len__": len(typed)}
	default:

		return "<scalar>"
	}
}

func sortByJSON(list []map[string]any) {
	sort.Slice(list, func(i, j int) bool { return jsonText(list[i]) < jsonText(list[j]) })
}

func TestHelperLongOperationAndCancellation(t *testing.T) {
	t.Run("long", func(t *testing.T) {
		fakeHelper(t, func(request map[string]any) map[string]any {
			time.Sleep(26 * time.Second)
			return map[string]any{"ok": true}
		})
		response, err := helperCall(context.Background(), "rebuild_rules", nil)
		checkedEqual(t, "long operation beyond 25s", map[string]any{"success": err == nil, "response": response}, map[string]any{"success": true, "response": map[string]any{"ok": true}})
	})
	t.Run("cancel", func(t *testing.T) {
		fakeHelper(t, func(request map[string]any) map[string]any {
			time.Sleep(300 * time.Millisecond)
			return map[string]any{"ok": true}
		})
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(20*time.Millisecond, cancel)
		started := time.Now()
		_, err := helperCall(ctx, "rebuild_rules", nil)
		checkedEqual(t, "cancellation", err != nil && time.Since(started) < 200*time.Millisecond, true)
	})
}

func TestAuthenticationReplayAndSource(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for counter, expected := range []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"} {
		code, err := hotp(secret, int64(counter))
		checkedEqual(t, fmt.Sprintf("HOTP %d", counter), map[string]any{"code": code, "ok": err == nil}, map[string]any{"code": expected, "ok": true})
	}
	stepPath := filepath.Join(t.TempDir(), "step")
	server := New(Config{TOTPStepPath: stepPath})
	code, err := hotp(secret, time.Now().Unix()/30)
	if err != nil {
		t.Fatal(err)
	}
	checkedEqual(t, "TOTP first use", server.checkTOTPCode(code, secret, true), true)
	checkedEqual(t, "TOTP replay", server.checkTOTPCode(code, secret, true), false)
	restarted := New(Config{TOTPStepPath: stepPath})
	checkedEqual(t, "TOTP replay across restart", restarted.checkTOTPCode(code, secret, true), false)
	server.oauthStates = map[string]time.Time{"fresh": time.Now(), "expired": time.Now().Add(-11 * time.Minute)}
	checkedEqual(t, "OAuth first state", server.consumeOAuthState("fresh"), true)
	checkedEqual(t, "OAuth replay", server.consumeOAuthState("fresh"), false)
	checkedEqual(t, "OAuth expiration", server.consumeOAuthState("expired"), false)
	request := httptest.NewRequest("POST", "/api/login", nil)
	request.RemoteAddr = "1.2.3.4:5678"
	request.Header.Set("X-Forwarded-For", "127.0.0.1")
	checkedEqual(t, "real peer address", remoteIP(request), "1.2.3.4")
	for attempt := 0; attempt < 5; attempt++ {
		server.authFailure("1.2.3.4")
	}
	checkedEqual(t, "shared auth limiter", server.authWait("1.2.3.4") > 0, true)
	server.authSuccess("1.2.3.4")
	checkedEqual(t, "successful auth clears limiter", server.authWait("1.2.3.4"), 0)
}
