package panel

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func helperOK(resp map[string]any) bool {
	value, _ := resp["ok"].(bool)
	if !value {
		return false
	}
	data, _ := resp["data"].(map[string]any)
	return numberValue(data["returncode"]) == 0
}

func helperStdout(resp map[string]any) string {
	data, _ := resp["data"].(map[string]any)
	value, _ := data["stdout"].(string)
	return value
}

func helperError(err error, resp map[string]any) string {
	if err != nil {
		return err.Error()
	}
	if value, ok := resp["message"].(string); ok && value != "" {
		return value
	}
	return "指标不可用"
}

func helperCall(ctx context.Context, op string, args map[string]any) (map[string]any, error) {
	if _, ok := ctx.Deadline(); !ok {
		timeout := 30 * time.Second
		if spec, exists := operationSpecs[op]; exists {
			timeout = time.Duration(spec.Timeout) * time.Second
		}
		if op == "set_panel_password" {
			timeout = 45 * time.Second
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	socket := os.Getenv("DNS_STACK_HELPER_SOCK")
	if socket == "" {
		socket = "/run/dns-stack/helper.sock"
	}
	network, address := "unix", socket
	if strings.HasPrefix(socket, "unix://") {
		address = strings.TrimPrefix(socket, "unix://")
	}
	if strings.HasPrefix(socket, "tcp://") {
		network = "tcp"
		address = strings.TrimPrefix(socket, "tcp://")
		host, _, splitErr := net.SplitHostPort(address)
		parsedHost := net.ParseIP(host)
		if splitErr != nil || parsedHost == nil || !parsedHost.IsLoopback() {
			return nil, fmt.Errorf("helper TCP 地址必须是回环地址")
		}
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("连不上管理助手 %s：%w——用 systemctl is-active dns-stack-helper 确认它在跑", socket, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if args == nil {
		args = map[string]any{}
	}
	if err = json.NewEncoder(conn).Encode(map[string]any{"op": op, "args": args}); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(io.LimitReader(conn, 8<<20)).ReadBytes('\n')
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("管理助手没有应答就断开了连接——查 journalctl -u dns-stack-helper")
		}
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(line, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func helperData(resp map[string]any) map[string]any {
	data, _ := resp["data"].(map[string]any)
	return data
}
