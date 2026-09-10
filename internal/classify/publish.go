package classify

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type PublishResult struct {
	Published bool              `json:"published"`
	Reason    string            `json:"reason,omitempty"`
	Changed   []string          `json:"changed,omitempty"`
	CDNPurged map[string]string `json:"cdn_purged,omitempty"`
}

type PublishOptions struct {
	AllowFullReset bool
	AllowIPReset   bool
}

func (e *Engine) gitDir() string {
	return filepath.Join(e.Config.StateDir, "git-state", "rules-repo")
}

func (e *Engine) git(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = e.gitDir()
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("git %s 失败: %v: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func (e *Engine) sshCommand() string {
	return fmt.Sprintf("ssh -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new",
		e.Config.DeployKeyPath)
}

func (e *Engine) EnsureRepo() error {
	if e.Config.Repository == "" {
		return guardf("GITHUB_REPOSITORY 未配置")
	}
	workdir := e.gitDir()
	if err := os.MkdirAll(filepath.Dir(workdir), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(workdir, ".git")); err != nil {
		url := fmt.Sprintf("git@github.com:%s.git", e.Config.Repository)
		cmd := exec.Command("git", "-c", "core.sshCommand="+e.sshCommand(),
			"clone", "--branch", e.Config.Branch, "--single-branch", url, workdir)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("克隆规则仓库失败: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	for _, pair := range [][2]string{
		{"core.sshCommand", e.sshCommand()},
		{"user.email", e.Config.CommitEmail},
		{"user.name", e.Config.CommitName},
	} {
		if _, err := e.git("config", pair[0], pair[1]); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) Publish(opts PublishOptions) (PublishResult, error) {
	workdir := e.gitDir()
	if _, err := os.Stat(filepath.Join(workdir, ".git")); err != nil {
		return PublishResult{}, guardf("git 工作区未初始化")
	}
	if _, err := e.git("fetch", "origin", e.Config.Branch); err != nil {
		return PublishResult{}, err
	}
	dirty, err := e.gitStatusPaths()
	if err != nil {
		return PublishResult{}, err
	}
	if len(dirty) > 0 {
		return PublishResult{}, guardf("git 工作区在发布前已有改动，禁止自动覆盖: %s",
			strings.Join(head(dirty, 5), ", "))
	}
	if err := e.syncWithRemote(); err != nil {
		return PublishResult{}, err
	}

	generations, modes := e.bundleState()
	generation := uniform(generations)
	if generation <= 0 {
		return PublishResult{}, guardf("本地四规则文件版本不一致或缺少 generated-at，禁止发布")
	}
	mode := modes[FileCN]
	if !sameMode(modes, mode) {
		return PublishResult{}, guardf("本地四规则文件 bundle-mode 不一致，禁止发布")
	}
	if !modeAllowed(mode, opts) {
		return PublishResult{}, guardf("不支持的规则包模式: %s", mode)
	}

	remoteGenerations, remoteModes, remoteComplete := e.remoteBundleState()
	if remoteComplete && sameMode(remoteModes, mode) && e.remoteBodiesMatch() {
		if remote := uniform(remoteGenerations); remote > 0 {
			if generation != remote {
				if err := e.restampBundle(remote); err != nil {
					return PublishResult{}, err
				}
			}
			return PublishResult{Published: false, Reason: "规则正文无变化，未提交"}, nil
		}
	}

	var remoteHighest int64
	for _, value := range remoteGenerations {
		if value > remoteHighest {
			remoteHighest = value
		}
	}
	if generation <= remoteHighest {
		generation = max(e.unixNow(), remoteHighest+1)
		if err := e.restampBundle(generation); err != nil {
			return PublishResult{}, err
		}
	}

	for _, name := range publishFiles {
		data, err := os.ReadFile(filepath.Join(e.publishDir(), name))
		if err != nil {
			return PublishResult{}, err
		}
		if err := os.WriteFile(filepath.Join(workdir, name), data, 0o644); err != nil {
			return PublishResult{}, err
		}
	}

	changed, err := e.gitStatusPaths()
	if err != nil {
		return PublishResult{}, err
	}
	allowed := make(map[string]struct{}, len(publishFiles))
	for _, name := range publishFiles {
		allowed[name] = struct{}{}
	}
	for _, path := range changed {
		if _, ok := allowed[path]; !ok {
			return PublishResult{}, guardf("git status 出现非预期文件变更，已中止发布，不提交不推送: %s", path)
		}
	}
	if len(changed) == 0 {
		return PublishResult{Published: false, Reason: "内容无变化，未提交"}, nil
	}

	if _, err := e.git(append([]string{"add", "--"}, publishFiles...)...); err != nil {
		return PublishResult{}, err
	}
	if _, err := e.git("commit", "-m", "Update DNS rules"); err != nil {
		return PublishResult{}, err
	}
	if _, err := e.git("push", "origin", "HEAD:"+e.Config.Branch); err != nil {
		return PublishResult{}, err
	}
	sort.Strings(changed)
	return PublishResult{Published: true, Changed: changed, CDNPurged: e.purgeJSDelivr()}, nil
}

func modeAllowed(mode string, opts PublishOptions) bool {
	switch mode {
	case ModeStandard, ModeColdStart:
		return true
	case ModeFullReset:
		return opts.AllowFullReset
	case ModeIPReset:
		return opts.AllowIPReset
	}
	return false
}

func (e *Engine) syncWithRemote() error {
	out, err := e.git("rev-list", "--left-right", "--count",
		fmt.Sprintf("HEAD...origin/%s", e.Config.Branch))
	if err != nil {
		return err
	}
	fields := strings.Fields(out)
	if len(fields) != 2 {
		return guardf("无法判断规则仓库与远端分支的同步状态")
	}
	var ahead, behind int
	if _, err := fmt.Sscan(fields[0], &ahead); err != nil {
		return guardf("无法判断规则仓库与远端分支的同步状态")
	}
	if _, err := fmt.Sscan(fields[1], &behind); err != nil {
		return guardf("无法判断规则仓库与远端分支的同步状态")
	}
	if ahead > 0 {
		return guardf("规则仓库本地领先 origin/%s %d 个提交，禁止自动覆盖或推送", e.Config.Branch, ahead)
	}
	if behind > 0 {
		if _, err := e.git("merge", "--ff-only", "origin/"+e.Config.Branch); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) gitStatusPaths() ([]string, error) {
	out, err := e.git("status", "--porcelain")
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, line := range strings.Split(out, "\n") {
		if len(line) < 4 {
			continue
		}
		path := strings.TrimSpace(line[3:])
		if from, to, renamed := strings.Cut(path, " -> "); renamed {
			paths = append(paths, strings.Trim(from, `"`), strings.Trim(to, `"`))
			continue
		}
		paths = append(paths, strings.Trim(path, `"`))
	}
	return paths, nil
}

func (e *Engine) remoteBundleState() (map[string]int64, map[string]string, bool) {
	generations := make(map[string]int64, len(publishFiles))
	modes := make(map[string]string, len(publishFiles))
	complete := true
	for _, name := range publishFiles {
		path := filepath.Join(e.gitDir(), name)
		if _, err := os.Stat(path); err != nil {
			complete = false
		}
		generation, mode := readHeader(path)
		generations[name] = generation
		modes[name] = mode
	}
	return generations, modes, complete
}

func (e *Engine) remoteBodiesMatch() bool {
	for _, name := range publishFiles {
		local := e.publishedBody(name)
		remote := readBody(filepath.Join(e.gitDir(), name))
		if len(local) != len(remote) {
			return false
		}
		for i := range local {
			if local[i] != remote[i] {
				return false
			}
		}
	}
	return true
}

func (e *Engine) purgeJSDelivr() map[string]string {
	if e.Config.Repository == "" {
		return map[string]string{"_": "repo 未知，跳过"}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	out := make(map[string]string, len(publishFiles))
	for _, name := range publishFiles {
		url := fmt.Sprintf("https://purge.jsdelivr.net/gh/%s@%s/%s",
			e.Config.Repository, e.Config.Branch, name)
		resp, err := client.Get(url)
		if err != nil {
			out[name] = "error: " + err.Error()
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			out[name] = "ok"
			continue
		}
		out[name] = fmt.Sprintf("http %d", resp.StatusCode)
	}
	return out
}

func head(values []string, n int) []string {
	if len(values) > n {
		return values[:n]
	}
	return values
}
