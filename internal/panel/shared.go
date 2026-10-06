package panel

import (
	"context"
	"net/http"
	"sync"
	"time"
)

type sharedResult struct {
	mu     sync.Mutex
	at     time.Time
	body   []byte
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
		go c.run(f, now, compute)
	}
	c.mu.Unlock()
	select {
	case <-f.done:
		return f.status, f.body
	case <-ctx.Done():
		return http.StatusServiceUnavailable, cancelledBody
	}
}

func (c *sharedResult) run(f *sharedFlight, now time.Time, compute func() (int, []byte)) {
	defer func() {
		if recover() != nil {
			f.status, f.body = http.StatusInternalServerError, []byte("{\"error\":\"内部错误\"}\n")
		}
		c.mu.Lock()
		if f.status == http.StatusOK {
			c.at, c.body = now, f.body
		}
		c.flight = nil
		c.mu.Unlock()
		close(f.done)
	}()
	f.status, f.body = compute()
}
