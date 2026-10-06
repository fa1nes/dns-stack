package backup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func (c Config) VerifyPackage(ctx context.Context, pkg, identity string) (Manifest, error) {
	if pkg == "" {
		found, err := c.newestPackage()
		if err != nil {
			return Manifest{}, err
		}
		pkg = found
		c.logf("[信息] 未指定包，自动选择最新的: %s", pkg)
	}
	if info, err := os.Stat(pkg); err != nil || !info.Mode().IsRegular() {
		return Manifest{}, fmt.Errorf("文件不存在: %s", pkg)
	}
	if identity == "" {
		identity = filepath.Join(c.SecretsDir, identityBasename)
	}
	work, err := os.MkdirTemp("", "dns-stack-verify-*")
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(work)

	c.logf("[信息] 正在解密...")
	payload := filepath.Join(work, "payload.tar.zst")
	if strings.HasSuffix(pkg, ".age") {
		if _, err := os.Stat(identity); err != nil {
			return Manifest{}, fmt.Errorf("找不到 age 私钥: %s", identity)
		}
		out, err := os.Create(payload)
		if err != nil {
			return Manifest{}, err
		}
		cmd := exec.CommandContext(ctx, "age", "-d", "-i", identity, pkg)
		cmd.Stdout = out
		cmd.Stderr = os.Stderr
		runErr := cmd.Run()
		out.Close()
		if runErr != nil {
			return Manifest{}, fmt.Errorf("解密失败: %w", runErr)
		}
	} else if err := copyFile(pkg, payload); err != nil {
		return Manifest{}, err
	}

	c.logf("[信息] 正在解压...")
	extracted := filepath.Join(work, "extracted")
	if err := os.MkdirAll(extracted, 0o755); err != nil {
		return Manifest{}, err
	}
	if err := extractTarZstd(ctx, payload, extracted); err != nil {
		return Manifest{}, err
	}
	inner, err := singleSubdir(extracted)
	if err != nil {
		return Manifest{}, err
	}

	c.logf("[信息] 正在校验 SHA256...")
	if err := VerifyChecksums(inner); err != nil {
		return Manifest{}, err
	}
	c.logf("[成功] 校验和全部匹配")

	mf, err := readManifest(inner)
	if err != nil {
		return Manifest{}, err
	}
	c.logf("[成功] 校验通过: %s", pkg)
	c.logf("        角色 %s / 架构 %s / 模式 %s / 生成于 %s",
		mf.Role, mf.Arch, mf.Mode, mf.CreatedAt)
	return mf, nil
}

func (c Config) newestPackage() (string, error) {
	var candidates []string
	for _, dir := range []string{c.ExportDir, c.BackupDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".tar.zst.age") {
				candidates = append(candidates, filepath.Join(dir, e.Name()))
			}
		}
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("用法: dns-stack verify <迁移包路径>(当前没有可自动选取的包)")
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, errA := os.Stat(candidates[i])
		b, errB := os.Stat(candidates[j])
		if errA != nil || errB != nil {
			return candidates[i] > candidates[j]
		}
		return a.ModTime().After(b.ModTime())
	})
	return candidates[0], nil
}
