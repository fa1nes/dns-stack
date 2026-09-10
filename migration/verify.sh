#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../scripts/backup-common.sh"

log_info() { echo "[信息] $*"; }
log_ok()   { echo "[成功] $*"; }
log_err()  { echo "[错误] $*" >&2; }
die()      { log_err "$1"; exit 1; }

PKG="${1:-}"
[[ -z "$PKG" ]] && die "用法: verify.sh <迁移包路径> [age身份文件路径]"
[[ -f "$PKG" ]] || die "文件不存在: $PKG"

IDENTITY="${2:-$SECRETS_DIR/backup-age-identity.txt}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log_info "正在解密..."
if [[ "$PKG" == *.age ]]; then
    [[ -f "$IDENTITY" ]] || die "找不到 age 私钥: $IDENTITY"
    age -d -i "$IDENTITY" "$PKG" > "$WORK/payload.tar.zst" || die "解密失败"
else
    cp "$PKG" "$WORK/payload.tar.zst"
fi

log_info "正在解压..."
zstd -d -q "$WORK/payload.tar.zst" -o "$WORK/payload.tar" || die "zstd 解压失败"
mkdir -p "$WORK/extracted"
tar -C "$WORK/extracted" -xf "$WORK/payload.tar" || die "tar 解包失败"

INNER_DIR="$(find "$WORK/extracted" -maxdepth 1 -mindepth 1 -type d | head -1)"
[[ -z "$INNER_DIR" ]] && die "包内没有找到数据目录"

log_info "正在校验 SHA256..."
if [[ -f "$INNER_DIR/checksums.sha256" ]]; then
    ( cd "$INNER_DIR" && sha256sum -c checksums.sha256 --quiet ) || die "校验和不匹配，文件可能损坏"
    log_ok "校验和全部匹配"
else
    log_err "包内没有 checksums.sha256"
    exit 1
fi

if [[ -f "$INNER_DIR/manifest.json" ]]; then
    log_ok "manifest.json:"
    cat "$INNER_DIR/manifest.json"
fi

log_ok "校验通过: $PKG"
