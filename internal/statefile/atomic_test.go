package statefile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteAtomicReplacesASymlinkInsteadOfWritingThroughIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("创建软链需要 Windows 开发者模式")
	}
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outside, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "direct4.txt")
	if err := os.Symlink(outside, target); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(target, []byte("1.2.3.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if body, _ := os.ReadFile(outside); string(body) != "untouched" {
		t.Fatalf("root 顺着状态目录里的软链把内容写到了外面：%q——面板组对这个目录有写权限，"+
			"能把任何一个文件换成指向 /etc 的软链", body)
	}
	info, err := os.Lstat(target)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o644 {
		t.Fatalf("目标应当变成一个 0644 的普通文件，实际 %v %v", info.Mode(), err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("目录里留下了临时文件：%v", entries)
	}
}

func TestWriteAtomicLeavesTheOldContentWhenItCannotWrite(t *testing.T) {
	target := filepath.Join(t.TempDir(), "file.txt")
	if err := WriteAtomic(target, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(filepath.Join(target, "child"), []byte("x"), 0o644); err == nil {
		t.Fatal("父路径是文件时应当报错")
	}
	if body, _ := os.ReadFile(target); string(body) != "old" {
		t.Fatalf("旧内容被破坏：%q", body)
	}
}
