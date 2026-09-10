package panel

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveListenPriority(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.env")
	if err := os.WriteFile(config, []byte("PANEL_LISTEN= 10.0.0.5:9090 \nPANEL_PORT=5353\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PANEL_LISTEN", "")
	checkedEqual(t, "命令行参数最优先", ResolveListen("1.2.3.4:8053", config), "1.2.3.4:8053")
	t.Setenv("PANEL_LISTEN", "192.168.1.1:8081")
	checkedEqual(t, "环境变量其次", ResolveListen("", config), "192.168.1.1:8081")
	t.Setenv("PANEL_LISTEN", "")
	checkedEqual(t, "config.env 再次(空白剔除)", ResolveListen("", config), "10.0.0.5:9090")
	checkedEqual(t, "都没有时回环兜底", ResolveListen("", filepath.Join(dir, "absent.env")), "127.0.0.1:8080")
	checkedEqual(t, "只写地址用 PANEL_PORT", ResolveListen("10.0.0.5", config), "10.0.0.5:5353")
	checkedEqual(t, "IPv6 完整写法原样保留", ResolveListen("[::1]:8080", config), "[::1]:8080")
	checkedEqual(t, "裸 IPv6 地址补方括号", ResolveListen("::1", config), "[::1]:5353")
	checkedEqual(t, "只写地址且 PANEL_PORT 缺失时 8080", ResolveListen("10.0.0.5", filepath.Join(dir, "absent.env")), "10.0.0.5:8080")
}

func TestIsLoopbackListen(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8080", "127.0.0.2:9000", "[::1]:8080", "localhost:8080"} {
		checkedEqual(t, "回环 "+addr, isLoopbackListen(addr), true)
	}
	for _, addr := range []string{"0.0.0.0:8080", "10.0.0.5:8080", "[::]:8080", "[2001:db8::1]:8080"} {
		checkedEqual(t, "非回环 "+addr, isLoopbackListen(addr), false)
	}
}

func TestPreStartCheck(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.env")
	if err := os.WriteFile(config, []byte("ROLE=cn-resolver\n"), 0600); err != nil {
		t.Fatal(err)
	}
	auth := filepath.Join(dir, "auth.json")
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	build := func(addr, configPath string) *Server {
		return New(Config{Addr: addr, ConfigPath: configPath, AuthPath: auth, CertPath: cert, KeyPath: key})
	}

	if err := build("127.0.0.1:8080", filepath.Join(dir, "absent.env")).PreStartCheck(); err == nil {
		t.Fatal("config.env 缺失应拒绝启动")
	}
	if err := build("127.0.0.1:8080", dir).PreStartCheck(); err == nil {
		t.Fatal("config.env 不可读(目录)应拒绝启动")
	}
	if err := build("127.0.0.1:8080", config).PreStartCheck(); err != nil {
		t.Fatalf("回环监听不需要密码与证书: %v", err)
	}
	if err := build("0.0.0.0:8080", config).PreStartCheck(); err == nil {
		t.Fatal("非回环监听且未设密码应拒绝启动")
	}

	hash := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := os.WriteFile(auth, []byte(`{"hash":"`+hash+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := build("0.0.0.0:8080", config).PreStartCheck(); err == nil {
		t.Fatal("非回环监听且读不到证书应拒绝启动")
	}
	if err := os.WriteFile(cert, []byte("cert"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := build("0.0.0.0:8080", config).PreStartCheck(); err == nil {
		t.Fatal("私钥缺失同样应拒绝启动")
	}
	if err := os.WriteFile(key, []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := build("0.0.0.0:8080", config).PreStartCheck(); err != nil {
		t.Fatalf("密码与证书齐全应放行: %v", err)
	}
}

func TestDBPathFallback(t *testing.T) {
	dir := t.TempDir()
	server := New(Config{DBPath: filepath.Join(dir, "collector.db")})
	checkedEqual(t, "两个库都不在时保持原路径", server.dbPath(), filepath.Join(dir, "collector.db"))
	classifier := filepath.Join(dir, "classifier.db")
	if err := os.WriteFile(classifier, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	checkedEqual(t, "回落 classifier.db", server.dbPath(), classifier)
	if err := os.WriteFile(filepath.Join(dir, "collector.db"), []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	checkedEqual(t, "collector.db 优先", server.dbPath(), filepath.Join(dir, "collector.db"))
	if _, err := New(Config{DBPath: filepath.Join(dir, "absent", "collector.db")}).openDB(); err == nil {
		t.Fatal("两个库都不在时 openDB 应报错(端点回 503)")
	}
}
