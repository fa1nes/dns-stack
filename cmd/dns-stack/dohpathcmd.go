package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/config"
)

const (
	defaultDoHPath  = "/dns-query"
	mosproxyConfig  = "/etc/dns-stack/mosproxy/config.yaml"
	expectedPathHit = 2
	probeAttempts   = 5
)

var (
	dohPathRe    = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{1,128}$`)
	yamlPathLine = regexp.MustCompile(`(?m)^([ \t]+path:[ \t]*)".*"`)
)

func cmdDoHPath(args []string) error {
	fs := flag.NewFlagSet("doh-path", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultPath, "配置文件")
	mosPath := fs.String("mosproxy-config", mosproxyConfig, "mosproxy 配置")
	rotate := fs.Bool("rotate", false, "随机生成一个新路径并切换")
	set := fs.String("set", "", "切换到指定路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case *rotate && *set != "":
		return fmt.Errorf("--rotate 与 --set 不能同时使用")
	case *rotate:
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		return applyDoHPath(*configPath, *mosPath, "/"+hex.EncodeToString(raw)+"/dns-query")
	case *set != "":
		return applyDoHPath(*configPath, *mosPath, *set)
	default:
		fmt.Print(renderDoHPath(*configPath))
		return nil
	}
}

func renderDoHPath(configPath string) string {
	keys := config.ReadKeys(configPath, "DOH_PATH", "PUBLIC_IPV4", "DOH_PORT")
	path := keys["DOH_PATH"]
	if path == "" {
		path = defaultDoHPath
	}
	host := keys["PUBLIC_IPV4"]
	if host == "" {
		host = "<服务器IP>"
	}
	port := keys["DOH_PORT"]
	if port == "" {
		port = "443"
	}
	hostport := host
	if port != "443" {
		hostport = host + ":" + port
	}
	isDefault := "0"
	if path == defaultDoHPath {
		isDefault = "1"
	}
	return fmt.Sprintf("DOH_PATH=%s\nDOH_URL=https://%s%s\nDOH_PATH_IS_DEFAULT=%s\n",
		path, hostport, path, isDefault)
}

func rewriteDoHPath(body []byte, newPath string) ([]byte, error) {
	hits := len(yamlPathLine.FindAll(body, -1))
	if hits != expectedPathHit {
		return nil, fmt.Errorf("配置里 path 字段有 %d 处(预期 %d 处)，已中止以免改坏配置", hits, expectedPathHit)
	}
	return yamlPathLine.ReplaceAll(body, []byte(`${1}"`+newPath+`"`)), nil
}

func applyDoHPath(configPath, mosPath, newPath string) error {
	if !dohPathRe.MatchString(newPath) {
		return fmt.Errorf("路径格式非法: %s\n要求以 / 开头，仅含字母数字和 . _ ~ - /，长度 2~129", newPath)
	}
	original, err := os.ReadFile(mosPath)
	if err != nil {
		return fmt.Errorf("找不到 %s: %w", mosPath, err)
	}
	updated, err := rewriteDoHPath(original, newPath)
	if err != nil {
		return err
	}
	backup := mosPath + ".prev"
	if err := os.WriteFile(backup, original, 0o640); err != nil {
		return err
	}
	if err := os.WriteFile(mosPath, updated, 0o640); err != nil {
		return err
	}

	rollback := func(reason string) error {
		fmt.Fprintf(os.Stderr, "[错误] %s，正在回滚配置\n", reason)
		os.WriteFile(mosPath, original, 0o640)
		exec.Command("systemctl", "restart", "mosproxy.service").Run()
		return fmt.Errorf("%s，已回滚到原配置", reason)
	}

	fmt.Println("[信息] 重启 mosproxy 使新路径生效...")
	if err := exec.Command("systemctl", "restart", "mosproxy.service").Run(); err != nil {
		return rollback("mosproxy 重启失败")
	}

	port := config.ReadKeys(configPath, "DOH_PORT")["DOH_PORT"]
	if port == "" {
		port = "443"
	}
	ok := false
	for i := 0; i < probeAttempts; i++ {
		time.Sleep(time.Second)
		out, err := exec.Command(selfBinary(), "doh-probe", "--path", newPath, "--port", port).Output()
		if err == nil && strings.TrimSpace(string(out)) == "ok" {
			ok = true
			break
		}
	}
	if !ok {
		return rollback("新路径自验失败")
	}

	if err := upsertConfigKey(configPath, "DOH_PATH", newPath); err != nil {
		return err
	}
	fmt.Println("[成功] DoH 路径已生效并自验通过")
	fmt.Print(renderDoHPath(configPath))
	fmt.Println()
	fmt.Println("[信息] 请把所有客户端(sing-box / Surge / iOS 描述文件)的 DoH 地址换成上面的 DOH_URL")
	fmt.Println("[信息] 旧地址即刻失效，未更新的客户端会解析失败")
	return nil
}

func upsertConfigKey(path, key, value string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	replaced := false
	for i, line := range lines {
		if strings.HasPrefix(line, key+"=") {
			lines[i] = key + "=" + value
			replaced = true
		}
	}
	if !replaced {
		lines = append(lines, key+"="+value)
	}
	info, err := os.Stat(path)
	mode := os.FileMode(0o640)
	if err == nil {
		mode = info.Mode().Perm()
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), mode)
}

func selfBinary() string {
	if path, err := os.Executable(); err == nil {
		return path
	}
	return "/opt/dns-stack/bin/dns-stack-go"
}
