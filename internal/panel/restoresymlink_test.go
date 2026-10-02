package panel

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRestoreNeverFollowsALinkPlantedInTheStateDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("创建软链需要 Windows 开发者模式")
	}
	secret := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(secret, []byte("root-only"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	planted := filepath.Join(state, "manual-gfw.txt")
	if err := os.Symlink(secret, planted); err != nil {
		t.Fatal(err)
	}
	backups := filepath.Join(state, "migration-restore-backup-1")
	if err := backupExisting(planted, backups, "manual/manual-gfw.txt"); err == nil {
		t.Fatal("备份时顺着软链读了 root 才能读的文件——面板用户把状态目录里的文件换成软链，" +
			"再触发迁移恢复，就能拿到 /etc/shadow 或 age 私钥的副本")
	}
	if err := writeRestored(planted, []byte("attacker")); err == nil {
		t.Fatal("恢复时覆盖了一个软链")
	}
	if body, _ := os.ReadFile(secret); string(body) != "root-only" {
		t.Fatalf("软链指向的文件被改写成 %q", body)
	}

	regular := filepath.Join(state, "manual-exclude.txt")
	if err := os.WriteFile(regular, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := backupExisting(regular, backups, "manual/manual-exclude.txt"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(backups, "manual", "manual-exclude.txt"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("备份副本应当只有 root 可读，实际 %v %v", info.Mode(), err)
	}
}
