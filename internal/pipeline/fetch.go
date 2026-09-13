package pipeline

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/netfetch"
)

const stepFetchBudget = 12 * time.Minute

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

func download(ctx context.Context, client *http.Client, url, dest, etag string) (int64, bool, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, false, "", err
	}
	req.Header.Set("User-Agent", "dns-stack")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, false, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return 0, true, "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return 0, false, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	temp := dest + ".part"
	file, err := os.Create(temp)
	if err != nil {
		return 0, false, "", err
	}
	written, copyErr := io.Copy(file, netfetch.Paced(resp.Body))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		os.Remove(temp)
		if copyErr != nil {
			return 0, false, "", copyErr
		}
		return 0, false, "", closeErr
	}
	return written, false, strings.TrimSpace(resp.Header.Get("ETag")), nil
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
		written, notModified, freshTag, err := download(ctx, netfetch.Client(item.local), spec.URL, spec.Dest, etag)
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
		if freshTag != "" {
			os.WriteFile(etagPath(spec.Dest), []byte(freshTag), 0o644)
		} else {
			os.Remove(etagPath(spec.Dest))
		}
		return FetchResult{Path: spec.Dest, Bytes: written, ViaTunnel: item.tunnel}, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("下载未成功")
	}
	return FetchResult{}, lastErr
}
