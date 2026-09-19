package helper

import (
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	"github.com/dns-stack/dns-stack/internal/stack"
)

const maxAccessEntries = 200

func listArg(args map[string]any, key string) []string {
	var raw []string
	switch value := args[key].(type) {
	case string:
		raw = strings.FieldsFunc(value, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ';'
		})
	case []any:
		for _, item := range value {
			if text, ok := item.(string); ok {
				raw = append(raw, strings.TrimSpace(text))
			}
		}
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func domainArgs(args map[string]any) ([]string, string) {
	entries := listArg(args, "domains")
	if len(entries) == 0 {
		return nil, "没有给出任何域名"
	}
	if len(entries) > maxAccessEntries {
		return nil, "一次最多处理 200 个域名"
	}
	out := make([]string, 0, len(entries))
	for _, item := range entries {
		safe, err := SafeDomain(item)
		if err != nil {
			return nil, err.Error()
		}
		out = append(out, safe)
	}
	return out, ""
}

func prefixArgs(args map[string]any) ([]string, string) {
	entries := listArg(args, "prefixes")
	if len(entries) == 0 {
		return nil, "没有给出任何网段"
	}
	if len(entries) > maxAccessEntries {
		return nil, "一次最多处理 200 个网段"
	}
	out := make([]string, 0, len(entries))
	for _, item := range entries {
		if strings.HasPrefix(item, "-") {
			return nil, "网段不能以 - 开头: " + item
		}
		if _, err := netip.ParsePrefix(item); err != nil {
			addr, addrErr := netip.ParseAddr(item)
			if addrErr != nil {
				return nil, "不是合法的 CIDR 或地址: " + item
			}
			item = netip.PrefixFrom(addr, addr.BitLen()).String()
		}
		out = append(out, item)
	}
	return out, ""
}

func (h *Helper) opBlocklistAdd(args map[string]any) result {
	names, message := domainArgs(args)
	if message != "" {
		return failure(message)
	}
	return h.run(append([]string{h.cli, "blocklist", "add"}, names...), 60*time.Second, true)
}

func (h *Helper) opBlocklistRemove(args map[string]any) result {
	names, message := domainArgs(args)
	if message != "" {
		return failure(message)
	}
	return h.run(append([]string{h.cli, "blocklist", "remove"}, names...), 60*time.Second, true)
}

func (h *Helper) opACLAdd(args map[string]any) result {
	prefixes, message := prefixArgs(args)
	if message != "" {
		return failure(message)
	}
	return h.run(append([]string{h.cli, "acl", "add", "--yes"}, prefixes...), 90*time.Second, false)
}

func (h *Helper) opACLRemove(args map[string]any) result {
	prefixes, message := prefixArgs(args)
	if message != "" {
		return failure(message)
	}
	return h.run(append([]string{h.cli, "acl", "remove", "--yes"}, prefixes...), 90*time.Second, false)
}

func (h *Helper) opACLApply(map[string]any) result {
	return h.run([]string{h.cli, "acl", "apply", "--yes"}, 90*time.Second, false)
}

func (h *Helper) opACLDisable(map[string]any) result {
	return h.run([]string{h.cli, "acl", "disable"}, 60*time.Second, false)
}

func (h *Helper) opACLStatus(map[string]any) result {
	table := stack.DefaultNFTTable
	if value := h.configValue("NFT_TABLE"); value != "" {
		table = value
	}
	probe := h.run([]string{"nft", "list", "chain", "inet", table, stack.ACLChain}, 15*time.Second, true)
	code, _ := probe["returncode"].(int)
	encoded, err := json.Marshal(map[string]any{"installed": code == 0, "table": table})
	if err != nil {
		return failure("序列化访问控制状态失败")
	}
	return result{"ok": true, "returncode": 0, "stdout": string(encoded), "stderr": ""}
}

func (h *Helper) opPruneBackups(map[string]any) result {
	return h.run([]string{h.cli, "backup", "--prune"}, 60*time.Second, true)
}

func (h *Helper) opDropStaleLogs(map[string]any) result {
	return h.run([]string{h.cli, "trim-logs", "--drop-stale"}, 60*time.Second, true)
}
