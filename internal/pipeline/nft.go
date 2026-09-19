package pipeline

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const nftChunk = 1000

func contextWithNFTTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 30*time.Second)
}

func nftRun(ctx context.Context, script string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	file, err := os.CreateTemp("", "dns-stack-nft-*.nft")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.WriteString(script); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "nft", "-f", file.Name())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft 加载失败，集合保持加载前状态（事务已回滚）: %v: %s",
			err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func renderSetScript(table, set string, entries []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\n", table)
	fmt.Fprintf(&b, "add set inet %s %s { type ipv4_addr; flags interval; auto-merge; }\n", table, set)
	fmt.Fprintf(&b, "flush set inet %s %s\n", table, set)
	for start := 0; start < len(entries); start += nftChunk {
		end := min(start+nftChunk, len(entries))
		fmt.Fprintf(&b, "add element inet %s %s { %s }\n",
			table, set, strings.Join(entries[start:end], ", "))
	}
	return b.String()
}

func (r *Runtime) LoadNFTSet(ctx context.Context, set string, prefixes []netip.Prefix) error {
	entries := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		entries = append(entries, prefix.String())
	}
	return nftRun(ctx, renderSetScript(r.Config.NFTTable, set, entries))
}

var nftEntry = regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`)

func (r *Runtime) NFTSetCount(ctx context.Context, set string) int {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nft", "list", "set", "inet", r.Config.NFTTable, set).Output()
	if err != nil {
		return 0
	}
	count := 0
	for _, field := range strings.Split(string(out), ",") {
		if nftEntry.MatchString(field) {
			count++
		}
	}
	return count
}

func HasNFT() bool {
	_, err := exec.LookPath("nft")
	return err == nil
}
