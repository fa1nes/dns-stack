#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/backup-common.sh"

INCLUDE_SECRETS=0
AUTOMATIC=0
for arg in "$@"; do
    case "$arg" in
        --include-secrets) INCLUDE_SECRETS=1 ;;
        --automatic) AUTOMATIC=1 ;;
    esac
done

log_info() { echo "[信息] $*"; }
log_ok()   { echo "[成功] $*"; }
log_err()  { echo "[错误] $*" >&2; }
log_warn() { echo "[警告] $*"; }

bc_check_disk_space || exit 1

BACKUP_ZSTD_LEVEL="$(bc_config_int BACKUP_ZSTD_LEVEL 6 1 19)"
BACKUP_ZSTD_THREADS="$(bc_config_int BACKUP_ZSTD_THREADS 2 1 8)"
BACKUP_RETENTION_DAILY="$(bc_config_int BACKUP_RETENTION_DAILY 3 1 365)"
BACKUP_RETENTION_WEEKLY="$(bc_config_int BACKUP_RETENTION_WEEKLY 2 1 104)"
export BACKUP_ZSTD_LEVEL BACKUP_ZSTD_THREADS

mkdir -p "$BACKUP_DIR"
TS="$(date '+%Y%m%d%H%M%S')"
PREFIX="daily"
if [[ "$AUTOMATIC" -eq 1 && "$(date +%u)" -eq 7 ]]; then
    PREFIX="weekly"  # 每周日跑一次的定时任务生成 weekly 前缀(第三十三节)
fi

WORK="$(mktemp -d)"
DEST="$WORK/dns-stack-backup-${TS}"
mkdir -p "$DEST"

log_info "正在收集配置和运行数据..."
bc_collect_payload "full" "$INCLUDE_SECRETS" 0 "$DEST"

log_info "正在生成 manifest 和校验和..."
bc_write_manifest "$DEST" "full" "$INCLUDE_SECRETS" 0
bc_write_checksums "$DEST"

log_info "正在打包压缩..."
ENCRYPT=0
[[ "$INCLUDE_SECRETS" -eq 1 ]] && ENCRYPT=1  # 含秘密数据的备份强制 age 加密(第二十七节)
OUT_FILE="$(bc_pack "$DEST" "$BACKUP_DIR/${PREFIX}-${TS}" "$ENCRYPT")"

log_info "正在验证压缩包..."
if [[ "$OUT_FILE" == *.age ]]; then
    age -d -i "$SECRETS_DIR/backup-age-identity.txt" "$OUT_FILE" | zstd -t -q
else
    zstd -t -q "$OUT_FILE"
fi

rm -rf "$WORK"

PREV_FILE="$(ls -1t "$BACKUP_DIR"/${PREFIX}-*.tar.zst* 2>/dev/null | sed -n '2p' || true)"
if [[ -n "$PREV_FILE" && -f "$PREV_FILE" ]]; then
    NEW_SZ="$(stat -c%s "$OUT_FILE" 2>/dev/null || echo 0)"
    PREV_SZ="$(stat -c%s "$PREV_FILE" 2>/dev/null || echo 0)"
    if [[ "$PREV_SZ" -gt 0 && "$NEW_SZ" -lt $(( PREV_SZ / 2 )) ]]; then
        log_warn "本次备份体积仅为上一份的 $(( NEW_SZ * 100 / PREV_SZ ))%"
        log_warn "  本次 ${NEW_SZ} 字节 / 上次 ${PREV_SZ} 字节"
        log_warn "  若非刚清理过数据，请检查数据库完整性: dns-stack health"
    fi
fi

bc_cleanup_old_backups "$BACKUP_RETENTION_DAILY" "$BACKUP_RETENTION_WEEKLY"

log_ok "备份完成: ${OUT_FILE}"
echo "$OUT_FILE"
