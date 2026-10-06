package ecszone

import (
	"errors"
	"fmt"
	"os"

	"github.com/dns-stack/dns-stack/internal/cidrutil"
	"github.com/dns-stack/dns-stack/internal/statefile"
)

func CheckPublishable(out string, merged []Row) error {
	if len(merged) == 0 {
		return errors.New("分片表为空，拒绝覆盖")
	}
	if index, bad := FirstOverlap(merged); bad {
		a, b := merged[index], merged[index+1]
		return fmt.Errorf("自检发现重叠区间，拒绝写入: %s-%s[%s] vs %s-%s[%s]",
			cidrutil.FormatAddr4(a.Lo), cidrutil.FormatAddr4(a.Hi), a.Zone,
			cidrutil.FormatAddr4(b.Lo), cidrutil.FormatAddr4(b.Hi), b.Zone)
	}
	if old := CountDataLines(out); old >= 100 && len(merged) < old*6/10 {
		return fmt.Errorf("打标网段从 %d 条骤降到 %d 条，拒绝覆盖，多半是归属库出了问题", old, len(merged))
	}
	return nil
}

func Publish(out string, merged []Row, reload func() int) (string, error) {
	if err := CheckPublishable(out, merged); err != nil {
		return "", err
	}
	previous, readErr := os.ReadFile(out)
	if err := statefile.WriteAtomic(out, []byte(Render(merged)), 0o644); err != nil {
		return "", err
	}
	switch code := reload(); code {
	case 0:
		return "mosproxy 管理接口连不上，分片表已落盘，下次启动时生效", nil
	case 200:
		return "mosproxy 已热加载新的分片表", nil
	default:
		if readErr != nil {
			os.Remove(out)
			return "", fmt.Errorf("mosproxy reload 返回 %d，首次生成的分片表已移除", code)
		}
		if err := statefile.WriteAtomic(out, previous, 0o644); err != nil {
			return "", fmt.Errorf("mosproxy reload 返回 %d，回滚也失败了: %w", code, err)
		}
		if recheck := reload(); recheck != 200 {
			return "", fmt.Errorf("mosproxy reload 返回 %d，已回滚到上一版，但回滚后 reload 仍返回 %d——问题不在分片表，检查 mosproxy 日志", code, recheck)
		}
		return "", fmt.Errorf("mosproxy reload 返回 %d，新分片表无法解析，已回滚到上一版", code)
	}
}
