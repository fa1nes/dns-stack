package panel

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type migrationEntry struct {
	archive string
	source  string
	note    string
}

type migrationFile struct {
	Path   string `json:"path"`
	Source string `json:"source"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Lines  int    `json:"lines,omitempty"`
	Note   string `json:"note,omitempty"`
}

type migrationSkipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type migrationManifest struct {
	Kind        string             `json:"kind"`
	Version     int                `json:"version"`
	GeneratedAt int64              `json:"generated_at"`
	Files       []migrationFile    `json:"files"`
	Missing     []migrationSkipped `json:"missing"`
	Excluded    []migrationSkipped `json:"excluded"`
	TotalBytes  int64              `json:"total_bytes"`
}

const migrationManifestVersion = 1

func migrationExcluded(cfg Config) []migrationSkipped {
	return []migrationSkipped{
		{Path: cfg.ConfigPath, Reason: "含部署凭据，迁移导出一律不带密钥；用 config.example.env 重新填"},
		{Path: filepath.ToSlash(filepath.Dir(cfg.AuthPath)), Reason: "面板密码、TOTP 密钥与证书副本，同上"},
		{Path: cfg.DBPath, Reason: "查询库体积大且可重建；观测数据用 /api/export?dataset=queries|domains 导出"},
		{Path: joinState(cfg, "chnroute/delegated-apnic-latest.txt"), Reason: "APNIC 原始快照，update-chnroute.sh 会重新下载"},
		{Path: joinState(cfg, "geoip"), Reason: "归属库体积大，update-geoip.sh 会重新下载"},
		{Path: joinState(cfg, "git-state"), Reason: "含规则仓库的 deploy key 与工作区，属于凭据"},
	}
}

func joinState(cfg Config, rel string) string {
	base := cfg.StateDir
	if base == "" {
		base = DefaultStateDir
	}
	return filepath.Join(base, filepath.FromSlash(rel))
}

func migrationEntries(cfg Config) []migrationEntry {
	ecs := cfg.ECSConfPath
	if ecs == "" {
		ecs = DefaultECSConfPath
	}
	entries := []migrationEntry{
		{archive: "manual/manual-cn-zones.txt", source: joinState(cfg, "manual-cn-zones.txt"),
			note: "人工指定需直连的区域，无法重新生成"},
		{archive: "manual/manual-gfw.txt", source: joinState(cfg, "manual-gfw.txt"),
			note: "人工 GFW 规则，无法重新生成"},
		{archive: "manual/manual-cn.txt", source: joinState(cfg, "manual-cn.txt"),
			note: "人工 CN 规则，无法重新生成"},
		{archive: "manual/manual-exclude.txt", source: joinState(cfg, "manual-exclude.txt"),
			note: "人工排除清单，无法重新生成"},
		{archive: "rules/cn.txt", source: joinState(cfg, "cn.txt")},
		{archive: "rules/gfw.txt", source: joinState(cfg, "gfw.txt")},
		{archive: "rules/cn-ip-cidr.txt", source: joinState(cfg, "cn-ip-cidr.txt")},
		{archive: "rules/polluted-ip-cidr.txt", source: joinState(cfg, "polluted-ip-cidr.txt")},
		{archive: "rules/base-cn.txt", source: joinState(cfg, "base-cn.txt"),
			note: "冷启动基线规则"},
		{archive: "state/architecture-epoch", source: joinState(cfg, "architecture-epoch")},
		{archive: "state/polluted-ip.txt", source: joinState(cfg, "polluted-ip.txt"),
			note: "污染 IP 观测，重新采集需要时间"},
		{archive: "state/ecs-ip-zone.txt", source: joinState(cfg, "ecs-ip-zone.txt")},
		{archive: "state/chnroute/direct4.txt", source: joinState(cfg, "chnroute/direct4.txt")},
		{archive: "state/chnroute/direct4-excluded.txt", source: joinState(cfg, "chnroute/direct4-excluded.txt")},
		{archive: "state/chnroute/cn-authority.txt", source: joinState(cfg, "chnroute/cn-authority.txt")},
		{archive: "state/chnroute/cn-zones-matched.txt", source: joinState(cfg, "chnroute/cn-zones-matched.txt")},
		{archive: "state/chnroute/cn-zones.txt", source: joinState(cfg, "chnroute/cn-zones.txt")},
		{archive: "state/chnroute/shared-anycast.txt", source: joinState(cfg, "chnroute/shared-anycast.txt")},
		{archive: "state/chnroute/shared-excluded.txt", source: joinState(cfg, "chnroute/shared-excluded.txt")},
		{archive: "state/chnroute/ecs-accum-state.tsv", source: joinState(cfg, "chnroute/ecs-accum-state.tsv"),
			note: "ECS 累积计时，缺了会让白名单重新从零累积"},
		{archive: "ecs/dns-stack-ecs.conf", source: ecs,
			note: "Unbound 的 ECS 白名单，update-cn-authority.sh 可重新生成"},
	}
	return entries
}

func WriteMigrationBundle(w io.Writer, cfg Config, now time.Time) (migrationManifest, error) {
	manifest := migrationManifest{
		Kind:        "dns-stack-migration",
		Version:     migrationManifestVersion,
		GeneratedAt: now.Unix(),
		Files:       []migrationFile{},
		Missing:     []migrationSkipped{},
		Excluded:    migrationExcluded(cfg),
	}
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	for _, entry := range migrationEntries(cfg) {
		data, err := os.ReadFile(entry.source)
		if err != nil {
			manifest.Missing = append(manifest.Missing, migrationSkipped{
				Path: entry.archive, Reason: readErrorReason(err),
			})
			continue
		}
		sum := sha256.Sum256(data)
		manifest.Files = append(manifest.Files, migrationFile{
			Path: entry.archive, Source: filepath.ToSlash(entry.source),
			Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:]),
			Lines: countPayloadLines(data), Note: entry.note,
		})
		manifest.TotalBytes += int64(len(data))
		if err := writeTarFile(tw, entry.archive, data, now); err != nil {
			return manifest, err
		}
	}
	sort.Slice(manifest.Missing, func(i, j int) bool {
		return manifest.Missing[i].Path < manifest.Missing[j].Path
	})

	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return manifest, err
	}
	if err := writeTarFile(tw, "manifest.json", append(encoded, '\n'), now); err != nil {
		return manifest, err
	}
	if err := tw.Close(); err != nil {
		return manifest, err
	}
	return manifest, gz.Close()
}

func readErrorReason(err error) string {
	if os.IsNotExist(err) {
		return "文件不存在"
	}
	if os.IsPermission(err) {
		return "无读取权限"
	}
	return "读取失败: " + err.Error()
}

func countPayloadLines(data []byte) int {
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		count++
	}
	return count
}

func writeTarFile(tw *tar.Writer, name string, data []byte, now time.Time) error {
	header := &tar.Header{
		Name: name, Mode: 0o644, Size: int64(len(data)),
		ModTime: now, Format: tar.FormatPAX,
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func (s *Server) migrationExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "只支持 GET"})
		return
	}
	now := s.now()
	name := fmt.Sprintf("dns-stack-migration-%s.tar.gz", now.UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")

	if _, err := WriteMigrationBundle(w, s.cfg, now); err != nil {

		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		panic(http.ErrAbortHandler)
	}
}
