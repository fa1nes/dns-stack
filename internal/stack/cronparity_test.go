package stack

import (
	"os"
	"strings"
	"testing"
)

func TestOffshoreJobsDeclareACronNeedleTheInstallerActuallyWrites(t *testing.T) {
	body, err := os.ReadFile("../../install-hk.sh")
	if err != nil {
		t.Skipf("读不到 install-hk.sh: %v", err)
	}
	installer := string(body)

	jobs := 0
	for _, module := range ForRole(RoleOffshore) {
		if module.Kind != KindJob {
			continue
		}
		jobs++
		if module.Cron == "" {
			t.Errorf("%s 是 cron 驱动的任务却没有 Cron 判据——"+
				"activeCronContains 拿到空串一律返回 false，"+
				"于是它永远显示「未调度」，哪怕 crontab 里明明有这一行", module.Unit)
			continue
		}
		if !strings.Contains(installer, module.Cron) {
			t.Errorf("%s 的 Cron 判据是 %q，install-hk.sh 写进 crontab 的命令里没有这段——"+
				"判据认不出自己装的那一行", module.Unit, module.Cron)
		}
	}
	if jobs == 0 {
		t.Skip("境外角色当前没有 cron 任务")
	}
}

func TestDeclaredLogFilesAreBareFileNames(t *testing.T) {
	declared := 0
	for _, module := range All() {
		if module.LogFile == "" {
			continue
		}
		declared++
		if strings.ContainsAny(module.LogFile, "/\\") {
			t.Errorf("%s 的 LogFile 是 %q——调用方会把它接在 /var/log/dns-stack 后面，"+
				"这里只能写文件名", module.Unit, module.LogFile)
		}
		if !strings.HasSuffix(module.LogFile, ".log") {
			t.Errorf("%s 的 LogFile 是 %q——僵尸日志清理只看 .log 结尾的文件，"+
				"不叫 .log 的名字进不了「活着」的集合", module.Unit, module.LogFile)
		}
	}
	if declared == 0 {
		t.Fatal("没有任何模块声明 LogFile——僵尸日志清理的白名单会是空的")
	}
}
