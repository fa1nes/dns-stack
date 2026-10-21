package ecszone

import (
	"errors"
	"fmt"

	"github.com/dns-stack/dns-stack/internal/cidrutil"
	"github.com/dns-stack/dns-stack/internal/metrics"
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
	return metrics.ReplaceAndReload(out, []byte(Render(merged)), "分片表", reload)
}
