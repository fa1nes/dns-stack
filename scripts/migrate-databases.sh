#!/usr/bin/env bash
set -Eeuo pipefail

CONFIG_FILE="${CONFIG_FILE:-/etc/dns-stack/config.env}"
STATE_DIR="${STATE_DIR:-/var/lib/dns-stack}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/dns-stack}"
ROLE="$(grep -E '^ROLE=' "$CONFIG_FILE" 2>/dev/null | head -1 | cut -d= -f2- || true)"
STAMP="$(date '+%Y%m%d%H%M%S')"
DEST="$BACKUP_DIR/schema-migration-$STAMP"
ACTIVE_UNITS=()

log() { echo "[数据库迁移] $*"; }
restart_units() {
    local unit
    for unit in "${ACTIVE_UNITS[@]}"; do
        systemctl restart "$unit" 2>/dev/null || true
    done
}
trap 'rc=$?; restart_units; exit $rc' EXIT

[[ "$EUID" -eq 0 ]] || { echo "请使用 sudo 运行" >&2; exit 1; }
command -v sqlite3 >/dev/null 2>&1 || { echo "缺少 sqlite3" >&2; exit 1; }
mkdir -p "$DEST"

WRITERS=(dns-stack-panel)
if [[ "$ROLE" == "cn-resolver" ]]; then
    WRITERS+=(mosproxy)
else
    WRITERS+=(dns-stack-classify dns-stack-verify)
fi
for unit in "${WRITERS[@]}"; do
    if systemctl is-active --quiet "$unit.service" 2>/dev/null; then
        ACTIVE_UNITS+=("$unit.service")
        systemctl stop "$unit.service"
    fi
done

while IFS= read -r -d '' database; do
    name="${database#${STATE_DIR}/}"
    mkdir -p "$DEST/$(dirname "$name")"
    sqlite3 "$database" ".backup '$DEST/$name'"
    log "已备份 $name"
done < <(find "$STATE_DIR" -type f -name '*.db' -print0 2>/dev/null)

GO_BIN=/opt/dns-stack/bin/dns-stack-go
if [[ -x "$GO_BIN" ]]; then
    if [[ "$ROLE" == "cn-resolver" ]]; then
        "$GO_BIN" collect stats >/dev/null || { echo "采集库迁移失败" >&2; exit 1; }
    else
        "$GO_BIN" classify status >/dev/null || { echo "分类库迁移失败" >&2; exit 1; }
    fi
    log "已按当前 schema 打开各数据库（缺表会自动建、旧列会就地迁移）"
else
    echo "缺少 $GO_BIN，无法执行 schema 迁移" >&2
    exit 1
fi

while IFS= read -r -d '' database; do
    result="$(sqlite3 "$database" 'PRAGMA integrity_check;' | head -1)"
    [[ "$result" == "ok" ]] || { echo "完整性检查失败: $database ($result)" >&2; exit 1; }
done < <(find "$STATE_DIR" -type f -name '*.db' -print0 2>/dev/null)

log "迁移完成；备份位于 $DEST"
