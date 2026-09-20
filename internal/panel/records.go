package panel

import (
	"database/sql"
	"fmt"

	"github.com/dns-stack/dns-stack/internal/collect"
)

var localOps = map[string]func(*Server, map[string]any) (bool, string){
	"delete_query":  (*Server).deleteQuery,
	"delete_domain": (*Server).deleteDomain,
	"delete_audit":  (*Server).deleteAudit,
}

func (s *Server) deleteQuery(args map[string]any) (bool, string) {
	id := numberValue(args["id"])
	if id <= 0 {
		return false, "缺少要删除的记录 id"
	}
	return s.deleteRows("查询记录", func(tx *sql.Tx) (int64, error) {
		return affected(tx.Exec("DELETE FROM query_events WHERE id = ?", id))
	})
}

func (s *Server) deleteAudit(args map[string]any) (bool, string) {
	id := numberValue(args["id"])
	if id <= 0 {
		return false, "缺少要删除的记录 id"
	}
	return s.deleteRows("审计记录", func(tx *sql.Tx) (int64, error) {
		return affected(tx.Exec("DELETE FROM audit_log WHERE id = ?", id))
	})
}

func (s *Server) deleteDomain(args map[string]any) (bool, string) {
	raw, _ := args["domain"].(string)
	domain := collect.NormalizeDomain(raw)
	if domain == "" {
		return false, "缺少要删除的域名"
	}
	return s.deleteRows("「"+domain+"」的统计", func(tx *sql.Tx) (int64, error) {
		events, err := affected(tx.Exec("DELETE FROM query_events WHERE domain = ?", domain))
		if err != nil {
			return 0, err
		}
		rows, err := affected(tx.Exec("DELETE FROM domains WHERE domain = ?", domain))
		if err != nil {
			return 0, err
		}
		return events + rows, nil
	})
}

func affected(result sql.Result, err error) (int64, error) {
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Server) deleteRows(subject string, remove func(*sql.Tx) (int64, error)) (bool, string) {
	db, err := s.openRW()
	if err != nil {
		return false, "数据库不可写：" + err.Error()
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		return false, "数据库不可写：" + err.Error()
	}
	count, err := remove(tx)
	if err != nil {
		_ = tx.Rollback()
		return false, "删除失败：" + err.Error()
	}
	if err := tx.Commit(); err != nil {
		return false, "删除失败：" + err.Error()
	}
	if count == 0 {
		return false, subject + "已经不存在了，可能刚被清理任务删掉"
	}
	return true, fmt.Sprintf("已删除 %s %d 行", subject, count)
}
