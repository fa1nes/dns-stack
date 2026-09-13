package pipeline

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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

func clientFor(localAddr string, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	if localAddr != "" {
		if addr, err := netip.ParseAddr(localAddr); err == nil {
			dialer.LocalAddr = &net.TCPAddr{IP: net.IP(addr.AsSlice())}
		}
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
			MaxIdleConnsPerHost:   2,
		},
	}
}

func etagPath(dest string) string {
	return filepath.Join(filepath.Dir(dest), "."+filepath.Base(dest)+".etag")
}

func download(ctx context.Context, client *http.Client, url, temp, etag string) (int64, bool, error) {
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
	file, err := os.Create(temp)
	if err != nil {
		return 0, false, err
	}
	written, copyErr := io.Copy(file, resp.Body)
	closeErr := file.Close()
	if copyErr != nil {
		os.Remove(temp)
		return 0, false, copyErr
	}
	if closeErr != nil {
		os.Remove(temp)
		return 0, false, closeErr
	}
	if tag := strings.TrimSpace(resp.Header.Get("ETag")); tag != "" {
		os.WriteFile(etagPath(strings.TrimSuffix(temp, ".part")), []byte(tag), 0o644)
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

	attempts := []struct {
		label  string
		local  string
		wait   time.Duration
		tunnel bool
	}{
		{"直连", "", 7 * time.Minute, false},
		{"隧道 " + r.Config.TunnelIf, r.Config.TunnelAddr, 7 * time.Minute, true},
	}

	var lastErr error
	for _, attempt := range attempts {
		written, notModified, err := download(ctx, clientFor(attempt.local, attempt.wait), spec.URL, temp, etag)
		if err != nil {
			lastErr = err
			r.Warnf("%s 经%s下载失败：%v", spec.Kind, attempt.label, err)
			continue
		}
		if notModified {
			return FetchResult{Path: spec.Dest, NotChanged: true, ViaTunnel: attempt.tunnel}, nil
		}
		if written < spec.MinBytes {
			lastErr = fmt.Errorf("仅 %d 字节（下限 %d），判定为残缺下载", written, spec.MinBytes)
			r.Warnf("%s 经%s下载残缺：%v", spec.Kind, attempt.label, lastErr)
			continue
		}
		if spec.Verify != nil {
			if err := spec.Verify(temp); err != nil {
				lastErr = fmt.Errorf("完整性校验未通过: %w", err)
				r.Warnf("%s 经%s下载后校验失败：%v", spec.Kind, attempt.label, err)
				continue
			}
		}
		if err := os.Chmod(temp, 0o644); err != nil {
			return FetchResult{}, err
		}
		if err := os.Rename(temp, spec.Dest); err != nil {
			return FetchResult{}, err
		}
		return FetchResult{Path: spec.Dest, Bytes: written, ViaTunnel: attempt.tunnel}, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("下载未成功")
	}
	return FetchResult{}, lastErr
}
