package pipeline

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"
)

const (
	MinSpeedBytes  = 8192
	SpeedWindow    = 20 * time.Second
	HeaderTimeout  = 20 * time.Second
	AttemptTimeout = 5 * time.Minute
	ConnectTimeout = 10 * time.Second
)

type pacedReader struct {
	inner  io.Reader
	last   time.Time
	acc    int64
	failed error
}

func (p *pacedReader) Read(buf []byte) (int, error) {
	if p.failed != nil {
		return 0, p.failed
	}
	n, err := p.inner.Read(buf)
	p.acc += int64(n)
	if p.last.IsZero() {
		p.last = time.Now()
	}
	if elapsed := time.Since(p.last); elapsed >= SpeedWindow {
		rate := p.acc * int64(time.Second) / int64(elapsed)
		if rate < MinSpeedBytes {
			p.failed = fmt.Errorf("持续 %s 平均速度 %d B/s 低于下限 %d B/s，判定为僵死连接",
				SpeedWindow, rate, MinSpeedBytes)
			return n, p.failed
		}
		p.last, p.acc = time.Now(), 0
	}
	return n, err
}

func netfetchPaced(r io.Reader) io.Reader { return &pacedReader{inner: r} }

func netfetchClient(localAddr string) *http.Client {
	dialer := &net.Dialer{Timeout: ConnectTimeout, KeepAlive: 30 * time.Second}
	if localAddr != "" {
		if addr, err := netip.ParseAddr(localAddr); err == nil {
			dialer.LocalAddr = &net.TCPAddr{IP: net.IP(addr.AsSlice())}
		}
	}
	return &http.Client{
		Timeout: AttemptTimeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   ConnectTimeout,
			ResponseHeaderTimeout: HeaderTimeout,
			MaxIdleConnsPerHost:   2,
		},
	}
}

func netfetchBytes(ctx context.Context, client *http.Client, url string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dns-stack")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(netfetchPaced(resp.Body), maxBytes))
}
