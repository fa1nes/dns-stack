package panel

import (
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	nodeCacheTTL = 10 * time.Minute
	nodeCacheCap = 8192
)

type nodeEntry struct {
	node map[string]any
	at   time.Time
}

type nodeCache struct {
	mu sync.Mutex
	m  map[string]nodeEntry
}

func (c *nodeCache) get(name string, now time.Time) (map[string]any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[name]
	if !ok || now.Sub(e.at) >= nodeCacheTTL {
		return nil, false
	}
	return e.node, true
}

func (c *nodeCache) put(name string, node map[string]any, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]nodeEntry{}
	}
	if len(c.m) >= nodeCacheCap {
		for k, e := range c.m {
			if now.Sub(e.at) >= nodeCacheTTL {
				delete(c.m, k)
			}
		}
		if len(c.m) >= nodeCacheCap {
			c.m = map[string]nodeEntry{}
		}
	}
	c.m[name] = nodeEntry{node: node, at: now}
}

func (s *Server) attachCachedNodes(items []map[string]any) []string {
	now := s.now()
	missing := []string{}
	for _, item := range items {
		name, _ := item["domain"].(string)
		if name == "" {
			continue
		}
		node, ok := s.nodes.get(name, now)
		if !ok {
			if len(missing) < resolveCap {
				missing = append(missing, name)
			}
			continue
		}
		if node != nil {
			item["node"] = node
		}
	}
	return missing
}

var nodeNamePattern = regexp.MustCompile(`^[a-z0-9_-]+(\.[a-z0-9_-]+)*\.?$`)

func (s *Server) domainNodes(w http.ResponseWriter, r *http.Request) {
	items := []map[string]any{}
	seen := map[string]bool{}
	for _, name := range strings.Split(strings.ToLower(r.URL.Query().Get("names")), ",") {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] || len(name) > 253 || !nodeNamePattern.MatchString(name) {
			continue
		}
		seen[name] = true
		items = append(items, map[string]any{"domain": name})
		if len(items) >= resolveCap {
			break
		}
	}
	s.attachResolvedNode(r.Context(), items)
	nodes := map[string]any{}
	for _, item := range items {
		if node, ok := item["node"]; ok {
			nodes[item["domain"].(string)] = node
		} else {
			nodes[item["domain"].(string)] = nil
		}
	}
	writeJSON(w, 200, map[string]any{"nodes": nodes})
}
