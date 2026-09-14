package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/dns-stack/dns-stack/internal/helper"
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

func TestDangerFlagAgreesWithHelper(t *testing.T) {
	for op, spec := range operationSpecs {
		if _, known := helper.DangerousOps[op]; spec.Dangerous && !known {
			t.Errorf("面板把 %s 标成危险操作会弹二次确认，但 helper 的 DangerousOps 里没有它——"+
				"绕开面板直接调 helper 就没有任何闸门", op)
		}
	}
	for op := range helper.DangerousOps {
		spec, listed := operationSpecs[op]
		if !listed {
			continue
		}
		if !spec.Dangerous {
			t.Errorf("helper 认为 %s 危险、会要求 confirm=true，但面板没标 Dangerous 因而不会带上它——"+
				"用户点下去只会拿到一条看不懂的拒绝", op)
		}
	}
}

func TestRoleGateAgreesWithHelper(t *testing.T) {
	for op, spec := range operationSpecs {
		want, gated := helper.RoleOps[op]
		if spec.Role != "" && !gated {
			t.Errorf("面板只把 %s 显示给 %s 角色，但 helper 对它没有任何角色闸门——"+
				"绕开面板直接调 helper socket，另一个角色照样能执行", op, spec.Role)
			continue
		}
		if spec.Role != "" && want != spec.Role {
			t.Errorf("%s 的角色两处不一致：面板要求 %s，helper 要求 %s", op, spec.Role, want)
		}
		if spec.Role == "" && gated {
			t.Errorf("helper 只允许 %s 执行 %s，但面板对所有角色都显示它——"+
				"另一个角色点下去只会拿到一条看不懂的拒绝", want, op)
		}
	}
	for op := range helper.RoleOps {
		if _, listed := operationSpecs[op]; !listed {
			t.Errorf("helper 给 %s 设了角色闸门，但面板的 operationSpecs 里没有它", op)
		}
	}
}

func TestEveryListedOperationHasASpec(t *testing.T) {
	for _, op := range operationOrder {
		if _, ok := operationSpecs[op]; !ok {
			t.Errorf("%s 在 operationOrder 里但没有 spec，面板会渲染出一个没有标签的按钮", op)
		}
	}
	for op := range operationSpecs {
		found := false
		for _, listed := range operationOrder {
			if listed == op {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s 有 spec 却不在 operationOrder 里，面板上永远看不见它", op)
		}
	}
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
