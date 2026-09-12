#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../scripts/backup-common.sh"

log_info() { echo "[信息] $*"; }
log_ok()   { echo "[成功] $*"; }
log_warn() { echo "[警告] $*"; }
log_err()  { echo "[错误] $*" >&2; }
die()      { log_err "$1"; exit 1; }

PKG="${1:-}"
[[ -z "$PKG" ]] && die "用法: dns-stack import <迁移包路径>"

log_info "[1/12] 检查文件..."
[[ -f "$PKG" ]] || die "文件不存在: $PKG"
[[ -r "$PKG" ]] || die "文件不可读，请检查权限"

log_info "[2/12] 检查磁盘空间..."
bc_check_disk_space || exit 1

log_info "[3/12] 解密..."
WORK="$(mktemp -d)"
IDENTITY="$SECRETS_DIR/backup-age-identity.txt"
if [[ "$PKG" == *.age ]]; then
    [[ -f "$IDENTITY" ]] || die "找不到 age 私钥，无法解密(该私钥应与生成该导出包的服务器一致，或手动放到 $IDENTITY)"
    age -d -i "$IDENTITY" "$PKG" > "$WORK/payload.tar.zst" || { rm -rf "$WORK"; die "解密失败"; }
else
    cp "$PKG" "$WORK/payload.tar.zst"
fi

log_info "[4/12] 解压到临时目录..."
zstd -d -q "$WORK/payload.tar.zst" -o "$WORK/payload.tar" || { rm -rf "$WORK"; die "解压失败"; }
mkdir -p "$WORK/extracted"
tar -C "$WORK/extracted" -xf "$WORK/payload.tar" || { rm -rf "$WORK"; die "解包失败"; }
INNER_DIR="$(find "$WORK/extracted" -maxdepth 1 -mindepth 1 -type d | head -1)"
[[ -z "$INNER_DIR" ]] && { rm -rf "$WORK"; die "包内没有数据目录"; }

log_info "[5/12] 校验 SHA256..."
( cd "$INNER_DIR" && sha256sum -c checksums.sha256 --quiet ) || { rm -rf "$WORK"; die "校验和不匹配"; }

log_info "[6/12] 读取 manifest..."
[[ -f "$INNER_DIR/manifest.json" ]] || { rm -rf "$WORK"; die "缺少 manifest.json"; }
PKG_ROLE="$(grep -oP '"role":\s*"\K[^"]+' "$INNER_DIR/manifest.json" || echo unknown)"
PKG_ARCH="$(grep -oP '"arch":\s*"\K[^"]+' "$INNER_DIR/manifest.json" || echo unknown)"

log_info "[7/12] 检查服务器角色..."
CUR_ROLE="$(bc_role)"
if [[ "$PKG_ROLE" != "$CUR_ROLE" && "$CUR_ROLE" != "unknown" ]]; then
    rm -rf "$WORK"
    die "导入包角色(${PKG_ROLE})与本机角色(${CUR_ROLE})不一致，拒绝导入"
fi

log_info "[8/12] 检查 CPU 架构..."
CUR_ARCH="$(uname -m)"
if [[ "$PKG_ARCH" != "$CUR_ARCH" ]]; then
    log_warn "导入包架构(${PKG_ARCH})与本机架构(${CUR_ARCH})不同，数据库/二进制可能不兼容，继续需人工确认"
fi

log_info "[9/12] 创建导入前备份(用于失败回滚)..."
PRE_IMPORT_BACKUP=""
if [[ -d "$STATE_DIR" ]] && [[ -n "$(ls -A "$STATE_DIR" 2>/dev/null)" ]]; then
    PRE_IMPORT_BACKUP="$(bash "$SCRIPT_DIR/../scripts/backup.sh" 2>&1 | tail -1)"
    log_ok "导入前备份: ${PRE_IMPORT_BACKUP}"
fi

rollback() {
    log_err "导入失败，正在回滚..."
    if [[ -n "$PRE_IMPORT_BACKUP" && -f "$PRE_IMPORT_BACKUP" ]]; then
        bash "$SCRIPT_DIR/../migration/import.sh" "$PRE_IMPORT_BACKUP" --no-rollback-recursion || \
            log_err "自动回滚也失败了，请人工检查 ${PRE_IMPORT_BACKUP}"
    fi
    rm -rf "$WORK"
    exit 1
}
if [[ "${2:-}" != "--no-rollback-recursion" ]]; then
    trap rollback ERR
fi

log_info "[10/12] 停止所有会写数据库的服务..."
DB_WRITERS=(dns-stack-classify dns-stack-verify dns-stack-panel mosproxy)
for svc in "${DB_WRITERS[@]}"; do
    systemctl stop "${svc}.service" 2>/dev/null || true
done
sleep 2

log_info "[11/12] 导入数据库、配置、规则、人工规则..."
if [[ -d "$INNER_DIR/state" ]]; then
    mkdir -p "$STATE_DIR"
    for f in "$INNER_DIR"/state/*; do
        [[ -e "$f" ]] || continue
        base="$(basename "$f")"
        [[ "$base" == "migration.tar.gz" ]] && continue
        if [[ "$base" == *.db ]]; then
            rm -f "$STATE_DIR/${base}-wal" "$STATE_DIR/${base}-shm"
        fi
        cp -a "$f" "$STATE_DIR/"
    done

    if [[ -f "$INNER_DIR/state/migration.tar.gz" ]]; then
        GO_BIN="${DNS_STACK_GO_BIN:-/opt/dns-stack/bin/dns-stack-go}"
        if [[ -x "$GO_BIN" ]]; then
            log_info "  恢复迁移包(规则 / 人工清单 / chnroute / ECS 累积计时)..."
            "$GO_BIN" migration-restore --bundle "$INNER_DIR/state/migration.tar.gz" \
                --state "$STATE_DIR" \
                || log_warn "  迁移包恢复未完全成功，请对照上面的跳过项人工确认"
        else
            log_warn "  缺少 $GO_BIN，备份里的规则与 chnroute 状态未恢复"
        fi
    fi
    while IFS= read -r -d '' dbf; do
        if command -v sqlite3 >/dev/null 2>&1; then
            if [[ "$(sqlite3 "$dbf" 'PRAGMA integrity_check;' 2>&1 | head -1)" != "ok" ]]; then
                log_warn "  $(basename "$dbf") 完整性检查未通过，尝试 REINDEX 修复..."
                sqlite3 "$dbf" 'REINDEX;' 2>/dev/null || true
                if [[ "$(sqlite3 "$dbf" 'PRAGMA integrity_check;' 2>&1 | head -1)" == "ok" ]]; then
                    log_ok "  $(basename "$dbf") 已修复"
                else
                    log_warn "  $(basename "$dbf") 仍有问题，请人工检查"
                fi
            fi
        fi
    done < <(find "$STATE_DIR" -type f -name '*.db' -print0 2>/dev/null)
fi
if [[ -f "$INNER_DIR/config/config.env" ]]; then
    cp -a "$INNER_DIR/config/config.env" "$CONFIG_FILE.imported"
    SKIP_KEYS="PUBLIC_IPV4 PUBLIC_IPV6"
    MERGED=0
    while IFS= read -r line; do
        [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
        key="${line%%=*}"
        val="${line#*=}"
        [[ " $SKIP_KEYS " == *" $key "* ]] && continue
        [[ -z "$val" ]] && continue
        if grep -qE "^${key}=" "$CONFIG_FILE" 2>/dev/null; then
            awk -v k="$key" -v l="$line" \
                'index($0, k "=") == 1 { print l; next } { print }' \
                "$CONFIG_FILE" > "$CONFIG_FILE.tmp" && mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
        else
            echo "$line" >> "$CONFIG_FILE"
        fi
        MERGED=$((MERGED + 1))
    done < "$INNER_DIR/config/config.env"
    if id -u dns-stack-panel >/dev/null 2>&1; then
        chgrp dns-stack-panel "$CONFIG_FILE" 2>/dev/null || true
        chmod 0640 "$CONFIG_FILE"
    else
        chmod 0644 "$CONFIG_FILE"
    fi
    log_ok "已合并 ${MERGED} 项旧配置(PUBLIC_IPV4/IPV6 保留新机器的值)"
    log_info "  旧配置原文另存为 ${CONFIG_FILE}.imported，可用于人工核对"
fi

if [[ -d "$INNER_DIR/secrets" ]]; then
    mkdir -p "$SECRETS_DIR"
    if [[ -n "$(ls -A "$SECRETS_DIR" 2>/dev/null)" ]]; then
        cp -a "$SECRETS_DIR" "${SECRETS_DIR}.pre-import-$(date '+%Y%m%d%H%M%S')" 2>/dev/null || true
    fi
    cp -a "$INNER_DIR/secrets/." "$SECRETS_DIR/"
    chmod 0600 "$SECRETS_DIR"/*.key "$SECRETS_DIR"/backup-age-identity.txt \
               "$SECRETS_DIR"/github_deploy_key 2>/dev/null || true
    if id -u dns-stack-panel >/dev/null 2>&1; then
        install -d -o dns-stack-panel -g dns-stack-panel -m 0750 "$SECRETS_DIR/panel"
        chown -R dns-stack-panel:dns-stack-panel "$SECRETS_DIR/panel" 2>/dev/null || true
        chmod 0400 "$SECRETS_DIR/panel/"* 2>/dev/null || true
    fi
    log_ok "已恢复机密文件(面板密码、备份密钥、证书)"
    log_warn "  证书是**旧服务器 IP** 的，对外服务前请执行: sudo dns-stack cert-renew"
fi

IMPORT_TS="$(date '+%Y%m%d%H%M%S')"
CONFIG_ROOT="$(dirname "$CONFIG_FILE")"

if [[ -d "$INNER_DIR/config/mosproxy" ]]; then
    mkdir -p "$CONFIG_ROOT/mosproxy"
    [[ -f "$CONFIG_ROOT/mosproxy/config.yaml" ]] && \
        cp -a "$CONFIG_ROOT/mosproxy/config.yaml" "$CONFIG_ROOT/mosproxy/config.yaml.pre-import-${IMPORT_TS}"
    cp -a "$INNER_DIR/config/mosproxy/." "$CONFIG_ROOT/mosproxy/"
    log_ok "已恢复 mosproxy 配置"
fi

if [[ -d "$INNER_DIR/config/unbound.conf.d" ]]; then
    mkdir -p /etc/unbound/unbound.conf.d
    [[ -f /etc/unbound/unbound.conf.d/dns-stack.conf ]] && \
        cp -a /etc/unbound/unbound.conf.d/dns-stack.conf \
              "/etc/unbound/unbound.conf.d/dns-stack.conf.pre-import-${IMPORT_TS}"
    cp -a "$INNER_DIR/config/unbound.conf.d/." /etc/unbound/unbound.conf.d/
    log_ok "已恢复 Unbound 配置"
fi

if [[ -d "$INNER_DIR/systemd" ]] && [[ -n "$(ls -A "$INNER_DIR/systemd" 2>/dev/null)" ]]; then
    cp -a "$INNER_DIR/systemd/." "$SYSTEMD_DIR/"
    systemctl daemon-reload
    log_ok "已恢复 systemd 单元并重新加载"
fi

log_warn "⚠️ 恢复过来的配置里含有**原服务器**的地址与路径，务必核对后再对外提供服务："
log_warn "   - mosproxy: 监听地址/端口、TLS 证书路径、上游(如 WireGuard 对端 10.100.0.x)"
log_warn "   - Unbound : interface 监听地址、access-control 网段"
log_warn "   - 证书本身需要按新服务器的 IP/域名重新签发: sudo dns-stack cert-renew"

log_info "修复权限..."
chmod 0710 "$SECRETS_DIR" 2>/dev/null || true
if id -u dns-stack-panel >/dev/null 2>&1; then
    chgrp dns-stack-panel "$SECRETS_DIR" 2>/dev/null || true
fi
chmod -R u+rwX "$STATE_DIR" 2>/dev/null || true

trap - ERR

log_info "[12/12] 重启服务并执行健康检查..."
RESTART_UNITS=(unbound)
[[ "$(bc_role)" == "cn-resolver" ]] && RESTART_UNITS+=(mosproxy)
RESTART_UNITS+=(dns-stack-helper dns-stack-panel)
for svc in "${RESTART_UNITS[@]}"; do
    systemctl reset-failed "${svc}.service" 2>/dev/null || true
    systemctl restart "${svc}.service" 2>/dev/null || log_warn "${svc} 重启失败，请查看 journalctl -u ${svc}"
done
sleep 4

HEALTH_OK=1
if command -v dig >/dev/null 2>&1; then
    dig @127.0.0.1 -p 5335 example.com A +time=3 +tries=1 +short >/dev/null 2>&1 || {
        log_warn "Unbound 递归解析未通过"; HEALTH_OK=0; }
fi
for svc in "${RESTART_UNITS[@]}"; do
    systemctl is-active --quiet "${svc}.service" \
        || { log_warn "${svc} 未处于运行状态: journalctl -u ${svc} -n 20"; HEALTH_OK=0; }
done
if [[ "$HEALTH_OK" -eq 1 ]]; then
    log_ok "健康检查通过：${RESTART_UNITS[*]} 均正常"
else
    log_warn "健康检查未完全通过，请执行 sudo dns-stack health 查看详情"
fi

rm -rf "$WORK"
log_ok "导入完成"
