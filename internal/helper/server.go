package helper

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	DefaultSocketPath   = "/run/dns-stack/helper.sock"
	DefaultLogPath      = "/var/log/dns-stack/helper.log"
	DefaultConfigPath   = "/etc/dns-stack/config.env"
	DefaultStackRoot    = "/opt/dns-stack/dns-stack"
	DefaultAuthPath     = "/etc/dns-stack/secrets/panel/auth.json"
	DefaultCLIPath      = "/usr/local/bin/dns-stack"
	DefaultGoBin        = "/opt/dns-stack/bin/dns-stack-go"
	DefaultLockPath     = "/run/lock/dns-stack-classifier.lock"
	DefaultMosproxyConf = "/etc/dns-stack/mosproxy/config.yaml"
	DefaultUnboundConf  = "/etc/unbound/unbound.conf.d/dns-stack.conf"
	DefaultStateDir     = "/var/lib/dns-stack"
	panelGroup          = "dns-stack-panel"
	requestTimeout      = 10 * time.Second
	maxRequestBytes     = 1 << 20
)

const execSlots = 4

type Config struct {
	SocketPath   string
	LogPath      string
	ConfigPath   string
	StackRoot    string
	AuthPath     string
	CLIPath      string
	GoBin        string
	LockPath     string
	MosproxyConf string
	UnboundConf  string
	StateDir     string
}

type Helper struct {
	sockPath     string
	configPath   string
	stackRoot    string
	authPath     string
	cli          string
	goBin        string
	lockPath     string
	mosproxyConf string
	unboundConf  string
	stateDir     string

	ops    map[string]func(map[string]any) result
	slots  chan struct{}
	logMu  sync.Mutex
	logOut *os.File
}

func fallback(value, def string) string {
	if value == "" {
		return def
	}
	return value
}

func New(cfg Config) *Helper {
	h := &Helper{
		sockPath:     fallback(cfg.SocketPath, DefaultSocketPath),
		configPath:   fallback(cfg.ConfigPath, DefaultConfigPath),
		stackRoot:    fallback(cfg.StackRoot, DefaultStackRoot),
		authPath:     fallback(cfg.AuthPath, DefaultAuthPath),
		cli:          fallback(cfg.CLIPath, DefaultCLIPath),
		goBin:        fallback(cfg.GoBin, DefaultGoBin),
		lockPath:     fallback(cfg.LockPath, DefaultLockPath),
		mosproxyConf: fallback(cfg.MosproxyConf, DefaultMosproxyConf),
		unboundConf:  fallback(cfg.UnboundConf, DefaultUnboundConf),
		stateDir:     fallback(cfg.StateDir, DefaultStateDir),
		slots:        make(chan struct{}, execSlots),
	}
	h.ops = h.operations()
	logPath := fallback(cfg.LogPath, DefaultLogPath)
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err == nil {
		if file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640); err == nil {
			h.logOut = file
		}
	}
	return h
}

func (h *Helper) Close() error {
	h.logMu.Lock()
	defer h.logMu.Unlock()
	if h.logOut == nil {
		return nil
	}
	err := h.logOut.Close()
	h.logOut = nil
	return err
}

func (h *Helper) log(message string) { h.write("INFO", message) }

func (h *Helper) warn(message string) { h.write("WARNING", message) }

func (h *Helper) write(level, message string) {
	line := time.Now().Format("2006-01-02 15:04:05") + " " + level + " " + message + "\n"
	h.logMu.Lock()
	defer h.logMu.Unlock()
	if h.logOut != nil {
		h.logOut.WriteString(line)
		return
	}
	os.Stderr.WriteString(line)
}

func (h *Helper) Dispatch(op string, args map[string]any) (resp map[string]any) {
	defer func() {
		if recovered := recover(); recovered != nil {
			h.warn(fmt.Sprintf("操作执行异常: %s %v", op, recovered))
			resp = map[string]any{"ok": false, "message": fmt.Sprintf("内部错误: %v", recovered)}
		}
	}()
	handler, known := h.ops[op]
	if !known {
		h.warn("拒绝未授权操作请求: " + strconv.Quote(op))
		return map[string]any{"ok": false, "message": "不允许的操作: " + op}
	}
	if DangerousOps[op] && !truthy(args["confirm"]) {
		h.warn("危险操作缺少确认: " + op)
		return map[string]any{"ok": false, "message": "危险操作 " + op + " 需要二次确认(confirm=true)"}
	}
	h.log("执行操作: " + op + " args=" + redactArgs(args))
	out := func() result {
		h.slots <- struct{}{}
		defer func() { <-h.slots }()
		return handler(args)
	}()
	if out == nil {
		return map[string]any{"ok": false, "message": "操作没有返回结果"}
	}

	if message, rejected := out[rejectionKey].(string); rejected {
		h.warn("操作参数非法: " + op + " " + message)
		return map[string]any{"ok": false, "message": message}
	}
	h.log(fmt.Sprintf("操作完成: %s rc=%v", op, out["returncode"]))
	return map[string]any{"ok": true, "data": map[string]any(out)}
}

func redactArgs(args map[string]any) string {
	safe := map[string]any{}
	for key, value := range args {
		if key == "confirm" {
			continue
		}
		if secretArgKeys[key] {
			safe[key] = redactedValue
			continue
		}
		safe[key] = value
	}
	encoded, err := json.Marshal(safe)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func (h *Helper) handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(requestTimeout))
	reader := bufio.NewReaderSize(conn, 4096)
	line, err := readLimitedLine(reader, maxRequestBytes)
	if err != nil || len(line) == 0 {
		return
	}
	var request struct {
		Op   string          `json:"op"`
		Args json.RawMessage `json:"args"`
	}
	var resp map[string]any
	if json.Unmarshal(line, &request) != nil {
		resp = map[string]any{"ok": false, "message": "请求不是合法 JSON"}
	} else {
		args := map[string]any{}
		if len(request.Args) > 0 && string(request.Args) != "null" {
			if json.Unmarshal(request.Args, &args) != nil {
				resp = map[string]any{"ok": false, "message": "args 必须是对象"}
			}
		}
		if resp == nil {

			conn.SetDeadline(time.Time{})
			resp = h.Dispatch(request.Op, args)
			conn.SetWriteDeadline(time.Now().Add(requestTimeout))
		}
	}
	encoded, err := json.Marshal(resp)
	if err != nil {
		return
	}
	conn.Write(append(encoded, '\n'))
}

func readLimitedLine(reader *bufio.Reader, limit int) ([]byte, error) {
	var out []byte
	for {
		chunk, more, err := reader.ReadLine()
		out = append(out, chunk...)
		if len(out) > limit {
			return nil, errors.New("请求过长")
		}
		if err != nil {
			return out, err
		}
		if !more {
			return out, nil
		}
	}
}

func (h *Helper) Serve() error {
	if err := os.MkdirAll(filepath.Dir(h.sockPath), 0o755); err != nil {
		return err
	}
	os.Remove(h.sockPath)
	listener, err := net.Listen("unix", h.sockPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(h.sockPath, 0o660); err != nil {
		return err
	}
	if group, err := user.LookupGroup(panelGroup); err == nil {
		gid, convErr := strconv.Atoi(group.Gid)
		if convErr == nil {
			os.Chown(h.sockPath, 0, gid)
		}
	} else {
		h.warn("系统里还没有 " + panelGroup + " 用户组，socket 属组暂时保持 root")
	}
	h.log("dns-stack-helper 已启动，监听 " + h.sockPath + " (角色: " + h.role() + ")")
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go h.handleConn(conn)
	}
}
