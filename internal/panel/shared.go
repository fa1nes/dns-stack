package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

type sharedResult struct {
	mu     sync.Mutex
	at     time.Time
	body   []byte
	gen    int
	flight *sharedFlight
}

type sharedFlight struct {
	done   chan struct{}
	status int
	body   []byte
}

var cancelledBody = []byte("{\"error\":\"请求已取消\"}\n")

func (c *sharedResult) get(ctx context.Context, now time.Time, ttl time.Duration, compute func() (int, []byte)) (int, []byte) {
	if ctx.Err() != nil {
		return http.StatusServiceUnavailable, cancelledBody
	}
	c.mu.Lock()
	if c.body != nil && now.Sub(c.at) < ttl {
		body := c.body
		c.mu.Unlock()
		return http.StatusOK, body
	}
	f := c.flight
	if f == nil {
		f = &sharedFlight{done: make(chan struct{}), status: http.StatusInternalServerError}
		c.flight = f
		go c.run(f, now, c.gen, compute)
	}
	c.mu.Unlock()
	select {
	case <-f.done:
		return f.status, f.body
	case <-ctx.Done():
		return http.StatusServiceUnavailable, cancelledBody
	}
}

func (c *sharedResult) run(f *sharedFlight, now time.Time, gen int, compute func() (int, []byte)) {
	defer func() {
		if recover() != nil {
			f.status, f.body = http.StatusInternalServerError, []byte("{\"error\":\"内部错误\"}\n")
		}
		c.mu.Lock()
		if f.status == http.StatusOK && gen == c.gen {
			c.at, c.body = now, f.body
		}
		if c.flight == f {
			c.flight = nil
		}
		c.mu.Unlock()
		close(f.done)
	}()
	f.status, f.body = compute()
}

func (c *sharedResult) forget() {
	c.mu.Lock()
	c.body = nil
	c.flight = nil
	c.gen++
	c.mu.Unlock()
}

type sharedResults struct {
	mu sync.Mutex
	m  map[string]*sharedResult
}

const sharedResultsCap = 32

func (c *sharedResults) entry(key string) *sharedResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.m[key]; e != nil {
		return e
	}
	if c.m == nil || len(c.m) >= sharedResultsCap {
		c.m = map[string]*sharedResult{}
	}
	e := &sharedResult{}
	c.m[key] = e
	return e
}

func (c *sharedResults) forget() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.m {
		e.forget()
	}
}

func encodeShared(status int, payload any) (int, []byte) {
	data, err := json.Marshal(payload)
	if err != nil {
		return http.StatusInternalServerError, []byte("{\"error\":\"编码失败\"}\n")
	}
	return status, append(data, '\n')
}

func writeShared(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (s *Server) forgetShared() {
	s.overviewShared.forget()
	s.statsShared.forget()
	s.statsRollup.reset()
}
