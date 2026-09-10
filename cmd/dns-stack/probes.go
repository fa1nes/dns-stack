package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/config"
	"github.com/dns-stack/dns-stack/internal/dnswire"
	"github.com/dns-stack/dns-stack/internal/helper"
	"github.com/dns-stack/dns-stack/internal/ipset"
)

func cmdDoHProbe(args []string) error {
	fs := flag.NewFlagSet("doh-probe", flag.ContinueOnError)
	host := fs.String("host", "127.0.0.1", "DoH 入口地址")
	port := fs.Int("port", 0, "DoH 端口(默认取 config.env 的 DOH_PORT，再退回 443)")
	path := fs.String("path", "", "DoH 路径(默认取 config.env 的 DOH_PATH，再退回 /dns-query)")
	name := fs.String("name", "www.taobao.com", "探测用域名")
	configPath := fs.String("config", config.DefaultPath, "config.env 路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	env := config.ReadKeys(*configPath, "DOH_PATH", "DOH_PORT")
	if *path == "" {
		*path = firstNonEmpty(env["DOH_PATH"], "/dns-query")
	}
	if *port == 0 {
		*port = 443
		if parsed, err := strconv.Atoi(env["DOH_PORT"]); err == nil && parsed > 0 {
			*port = parsed
		}
	}
	packet, err := dnswire.BuildQuery(0x1234, *name, dnswire.TypeA)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	endpoint := net.JoinHostPort(*host, fmt.Sprint(*port))
	url := fmt.Sprintf("https://%s%s", endpoint, *path)
	where := fmt.Sprintf("%s（路径 %d 字符）", endpoint, len(*path))
	resp, err := client.Post(url, "application/dns-message", bytes.NewReader(packet))
	if err != nil {
		return probeFailed("连接 %s 失败: %s", where, redactPath(err, *path))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	switch {
	case err != nil:
		return probeFailed("读 %s 的响应失败: %s", where, redactPath(err, *path))
	case resp.StatusCode != http.StatusOK:
		return probeFailed("%s 返回 HTTP %d，与 config.env 的 DOH_PATH 是否一致？",
			where, resp.StatusCode)
	case len(body) <= 12:
		return probeFailed("%s 的响应体只有 %d 字节，不是完整的 DNS 报文", where, len(body))
	}
	fmt.Println("ok")
	return nil
}

func redactPath(err error, path string) string {
	text := err.Error()
	if path == "" || path == "/" {
		return text
	}
	return strings.ReplaceAll(text, path, "<DOH_PATH>")
}

func probeFailed(format string, args ...any) error {
	fmt.Println("bad")
	fmt.Fprintf(os.Stderr, "doh-probe: "+format+"\n", args...)
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

var ipv4Pattern = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

func cmdHelperProbe(args []string) error {
	fs := flag.NewFlagSet("helper-probe", flag.ContinueOnError)
	sock := fs.String("socket", helper.DefaultSocketPath, "helper unix socket 路径")
	unit := fs.String("unit", "mosproxy", "要抽查日志的单元")
	lines := fs.Int("lines", 200, "抽查行数")
	if err := fs.Parse(args); err != nil {
		return err
	}
	conn, err := net.DialTimeout("unix", *sock, 5*time.Second)
	if err != nil {
		fmt.Println("-1")
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	request, err := json.Marshal(map[string]any{
		"op":   "logs",
		"args": map[string]any{"unit": *unit, "lines": *lines},
	})
	if err != nil {
		return err
	}
	if _, err := conn.Write(append(request, '\n')); err != nil {
		fmt.Println("-1")
		return nil
	}
	var buf bytes.Buffer
	chunk := make([]byte, 65536)
	for !bytes.Contains(buf.Bytes(), []byte("\n")) {
		n, err := conn.Read(chunk)
		if n > 0 {
			buf.Write(chunk[:n])
		}
		if err != nil {
			break
		}
	}
	var envelope struct {
		Data struct {
			Stdout string `json:"stdout"`
		} `json:"data"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &envelope); err != nil {
		fmt.Println("-1")
		return nil
	}
	fmt.Println(countLeakedAddresses(envelope.Data.Stdout))
	return nil
}

func countLeakedAddresses(text string) int {
	leaked := 0
	for _, match := range ipv4Pattern.FindAllString(text, -1) {
		addr, err := netip.ParseAddr(match)
		if err != nil || !addr.Is4() {
			continue
		}
		if !ipset.IsGlobalAddr(addr) {
			continue
		}
		if strings.HasSuffix(match, ".x.x") {
			continue
		}
		leaked++
	}
	return leaked
}
