package metrics

import (
	"fmt"
	"os"

	"github.com/dns-stack/dns-stack/internal/statefile"
)

func ReplaceAndReload(path string, content []byte, what string, reload func() int) (string, error) {
	previous, readErr := os.ReadFile(path)
	if err := statefile.WriteAtomic(path, content, 0o644); err != nil {
		return "", err
	}
	switch code := reload(); code {
	case 0:
		return fmt.Sprintf("mosproxy 管理接口连不上，%s已落盘，下次启动时生效", what), nil
	case 200:
		return fmt.Sprintf("mosproxy 已热加载新的%s", what), nil
	default:
		if readErr != nil {
			os.Remove(path)
			return "", fmt.Errorf("mosproxy reload 返回 %d，首次生成的%s已移除", code, what)
		}
		if err := statefile.WriteAtomic(path, previous, 0o644); err != nil {
			return "", fmt.Errorf("mosproxy reload 返回 %d，回滚也失败了: %w", code, err)
		}
		if recheck := reload(); recheck != 200 {
			return "", fmt.Errorf("mosproxy reload 返回 %d，已回滚到上一版，但回滚后 reload 仍返回 %d——问题不在%s，检查 mosproxy 日志", code, recheck, what)
		}
		return "", fmt.Errorf("mosproxy reload 返回 %d，新%s无法解析，已回滚到上一版", code, what)
	}
}
