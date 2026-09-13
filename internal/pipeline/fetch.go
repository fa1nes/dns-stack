package pipeline

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	minSpeedBytes   = 8192
	speedWindow     = 20 * time.Second
	headerTimeout   = 20 * time.Second
	attemptTimeout  = 5 * time.Minute
	connectTimeout  = 10 * time.Second
	stepFetchBudget = 12 * time.Minute
)

var tunnelFirstHosts = []string{"github.com", "objects.githubusercontent.com", "raw.githubusercontent.com"}

type FetchResult struct {
	Path       string
	Bytes      int64
	NotChanged bool
	ViaTunnel  bool
}

type fetchSpec struct {
	Kind     string
	URL      string
	Dest     string
	MinBytes int64
	Verify   func(path string) error
}

type paceReader struct {
	inner  io.Reader
	last   time.Time
	acc    int64
	total  int64
	failed error
}

func (p *paceReader) Read(buf []byte) (int, error) {
	if p.failed != nil {
		return 0, p.failed
	}
	n, err := p.inner.Read(buf)
	p.acc += int64(n)
	p.total += int64(n)
	if p.last.IsZero() {
		p.last = time.Now()
	}
	if elapsed := time.Since(p.last); elapsed >= speedWindow {
		rate := p.acc * int64(time.Second) / int64(elapsed)
		if rate < minSpeedBytes {
			p.failed = fmt.Errorf("持续 %s 平均速度 %d B/s 低于下限 %d B/s，判定为僵死连接",
				speedWindow, rate, minSpeedBytes)
			return n, p.failed
		}
		p.last, p.acc = time.Now(), 0
	}
	return n, err
}

func clientFor(localAddr string) *http.Client {
	dialer := &net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}
	if localAddr != "" {
		if addr, err := netip.ParseAddr(localAddr); err == nil {
			dialer.LocalAddr = &net.TCPAddr{IP: net.IP(addr.AsSlice())}
		}
	}
	return &http.Client{
		Timeout: attemptTimeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   connectTimeout,
			ResponseHeaderTimeout: headerTimeout,
			MaxIdleConnsPerHost:   2,
		},
	}
}

func etagPath(dest string) string {
	return filepath.Join(filepath.Dir(dest), "."+filepath.Base(dest)+".etag")
}

func prefersTunnel(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	for _, known := range tunnelFirstHosts {
		if host == known || strings.HasSuffix(host, "."+known) {
			return true
		}
	}
	return false
}

func download(ctx context.Context, client *http.Client, url, dest, etag string) (int64, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, false, err
	}
	req.Header.Set("User-Agent", "dns-stack")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return 0, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return 0, false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	temp := dest + ".part"
	file, err := os.Create(temp)
	if err != nil {
		return 0, false, err
	}
	paced := &paceReader{inner: resp.Body}
	written, copyErr := io.Copy(file, paced)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		os.Remove(temp)
		if copyErr != nil {
			return 0, false, copyErr
		}
		return 0, false, closeErr
	}
	if tag := strings.TrimSpace(resp.Header.Get("ETag")); tag != "" {
		os.WriteFile(etagPath(dest), []byte(tag), 0o644)
	}
	return written, false, nil
}

func (r *Runtime) Fetch(ctx context.Context, spec fetchSpec) (FetchResult, error) {
	if strings.TrimSpace(spec.URL) == "" {
		return FetchResult{}, fmt.Errorf("%s 没有配置下载地址", spec.Kind)
	}
	if err := os.MkdirAll(filepath.Dir(spec.Dest), 0o755); err != nil {
		return FetchResult{}, err
	}
	temp := spec.Dest + ".part"
	defer os.Remove(temp)

	var etag string
	if _, err := os.Stat(spec.Dest); err == nil {
		if data, err := os.ReadFile(etagPath(spec.Dest)); err == nil {
			etag = strings.TrimSpace(string(data))
		}
	}

	type attempt struct {
		label  string
		local  string
		tunnel bool
	}
	attempts := []attempt{
		{"直连", "", false},
		{"隧道 " + r.Config.TunnelIf, r.Config.TunnelAddr, true},
	}
	if prefersTunnel(spec.URL) {
		attempts[0], attempts[1] = attempts[1], attempts[0]
	}

	var lastErr error
	for _, item := range attempts {
		if ctx.Err() != nil {
			return FetchResult{}, ctx.Err()
		}
		written, notModified, err := download(ctx, clientFor(item.local), spec.URL, spec.Dest, etag)
		if err != nil {
			lastErr = err
			r.Warnf("%s 经%s下载失败：%v", spec.Kind, item.label, err)
			continue
		}
		if notModified {
			return FetchResult{Path: spec.Dest, NotChanged: true, ViaTunnel: item.tunnel}, nil
		}
		if written < spec.MinBytes {
			lastErr = fmt.Errorf("仅 %d 字节（下限 %d），判定为残缺下载", written, spec.MinBytes)
			r.Warnf("%s 经%s下载残缺：%v", spec.Kind, item.label, lastErr)
			continue
		}
		if spec.Verify != nil {
			if err := spec.Verify(temp); err != nil {
				lastErr = fmt.Errorf("完整性校验未通过: %w", err)
				r.Warnf("%s 经%s下载后校验失败：%v", spec.Kind, item.label, err)
				continue
			}
		}
		if err := os.Chmod(temp, 0o644); err != nil {
			return FetchResult{}, err
		}
		if err := os.Rename(temp, spec.Dest); err != nil {
			return FetchResult{}, err
		}
		return FetchResult{Path: spec.Dest, Bytes: written, ViaTunnel: item.tunnel}, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("下载未成功")
	}
	return FetchResult{}, lastErr
}
