#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../scripts/backup-common.sh"

log_info() { echo "[信息] $*"; }
log_ok()   { echo "[成功] $*"; }
log_err()  { echo "[错误] $*" >&2; }
die()      { log_err "$1"; exit 1; }

MODE=""
INCLUDE_LOGS=0
INCLUDE_SECRETS=0
for arg in "$@"; do
    case "$arg" in
        --mode) : ;;
        --mode=*) MODE="${arg#--mode=}" ;;
        config|state|full) MODE="$arg" ;;
        --include-logs) INCLUDE_LOGS=1 ;;
        --include-secrets) INCLUDE_SECRETS=1 ;;
    esac
done
prev=""
for arg in "$@"; do
    if [[ "$prev" == "--mode" ]]; then MODE="$arg"; fi
    prev="$arg"
done

if [[ -z "$MODE" ]]; then
    if [[ -t 0 ]]; then
        echo "请选择导出类型："
        echo
        echo "1. 仅导出配置"
        echo "2. 导出配置和运行数据"
        echo "3. 导出完整迁移包"
        echo "0. 取消"
        read -r -p "请输入选项: " choice
        case "$choice" in
            1) MODE="config" ;;
            2) MODE="state" ;;
            3) MODE="full" ;;
            *) echo "已取消"; exit 0 ;;
        esac
    else
        die "非交互模式必须指定 --mode config|state|full"
    fi
fi

[[ "$MODE" == "full" ]] && INCLUDE_SECRETS=1

log_info "检查运行环境..."
bc_check_disk_space || exit 1
mkdir -p "$EXPORT_DIR"

ROLE="$(bc_role)"
TS="$(date '+%Y%m%d%H%M%S')"
WORK="$(mktemp -d)"
DEST="$WORK/dns-stack-export"
mkdir -p "$DEST"

log_info "正在创建数据库一致性备份..."
log_info "正在收集配置和状态(模式: ${MODE})..."
bc_collect_payload "$MODE" "$INCLUDE_SECRETS" "$INCLUDE_LOGS" "$DEST"

log_info "正在生成 manifest.json..."
bc_write_manifest "$DEST" "$MODE" "$INCLUDE_SECRETS" "$INCLUDE_LOGS"

log_info "正在生成 checksums.sha256..."
bc_write_checksums "$DEST"

log_info "正在打包压缩..."
OUT_BASENAME="dns-stack-${ROLE}-${TS}"
TAR_ZST="$WORK/${OUT_BASENAME}.tar.zst"
tar -C "$WORK" -c "dns-stack-export" | zstd -q -19 -T0 -o "$TAR_ZST"

log_info "正在加密(age)..."
if [[ ! -f "$SECRETS_DIR/backup-age-identity.txt" ]]; then
    mkdir -p "$SECRETS_DIR"
    age-keygen -o "$SECRETS_DIR/backup-age-identity.txt" 2>/dev/null
    chmod 0600 "$SECRETS_DIR/backup-age-identity.txt"
    grep '^# public key:' "$SECRETS_DIR/backup-age-identity.txt" | sed 's/# public key: //' > "$SECRETS_DIR/backup-age-recipient.txt"
fi
FINAL_FILE="$EXPORT_DIR/${OUT_BASENAME}.tar.zst.age"
age -r "$(cat "$SECRETS_DIR/backup-age-recipient.txt")" -o "$FINAL_FILE" "$TAR_ZST"

log_info "正在做解密测试..."
age -d -i "$SECRETS_DIR/backup-age-identity.txt" "$FINAL_FILE" | zstd -t -q || die "解密测试失败，导出包可能损坏"

log_info "正在做 SHA256 校验..."
sha256sum "$FINAL_FILE" > "${FINAL_FILE}.sha256"

rm -rf "$WORK"
log_ok "导出完成: ${FINAL_FILE}"
echo "$FINAL_FILE"
