package panel

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (s *Server) migrationInboxDir() string {
	return joinState(s.cfg, "migration-inbox")
}

func (s *Server) migrationImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "只支持 POST"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MigrationMaxBundleBytes+(1<<20))
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "读取上传失败: " + err.Error()})
		return
	}
	file, header, err := r.FormFile("bundle")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "缺少 bundle 文件字段"})
		return
	}
	defer file.Close()
	if header.Size > MigrationMaxBundleBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge,
			map[string]any{"error": fmt.Sprintf("迁移包超过 %d MB 上限", MigrationMaxBundleBytes>>20)})
		return
	}

	inbox := s.migrationInboxDir()
	if err := os.MkdirAll(inbox, 0o750); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "无法准备暂存目录: " + err.Error()})
		return
	}
	name := fmt.Sprintf("upload-%s.tar.gz", s.now().UTC().Format("20060102-150405"))
	staged := filepath.Join(inbox, name)
	dst, err := os.OpenFile(staged, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "无法写入暂存文件: " + err.Error()})
		return
	}
	written, copyErr := io.Copy(dst, io.LimitReader(file, MigrationMaxBundleBytes+1))
	closeErr := dst.Close()
	if copyErr != nil || closeErr != nil || written > MigrationMaxBundleBytes {
		os.Remove(staged)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "暂存迁移包失败或超过上限"})
		return
	}

	dryRun := r.FormValue("dry_run") == "true" || r.URL.Query().Get("dry_run") == "true"
	args := map[string]any{"path": staged, "dry_run": "false"}
	if dryRun {
		args["dry_run"] = "true"
	}
	if !dryRun {
		args["confirm"] = true
	}
	raw, helperErr := helperCall(r.Context(), "migration_restore", args)

	if !dryRun {
		os.Remove(staged)
	}
	s.pruneMigrationInbox(inbox)

	if helperErr != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "helper 调用失败: " + helperErr.Error()})
		return
	}
	payload := map[string]any{"dry_run": dryRun, "bytes": written}
	for key, value := range raw {
		payload[key] = value
	}
	if stdout, ok := raw["stdout"].(string); ok && strings.TrimSpace(stdout) != "" {
		var report RestoreReport
		if err := json.Unmarshal([]byte(stdout), &report); err == nil {
			payload["report"] = report
		}
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) pruneMigrationInbox(inbox string) {
	entries, err := os.ReadDir(inbox)
	if err != nil {
		return
	}
	cutoff := s.now().Add(-24 * time.Hour)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		os.Remove(filepath.Join(inbox, entry.Name()))
	}
}
