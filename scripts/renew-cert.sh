#!/usr/bin/env bash
set -Eeuo pipefail

CERT_FILE="/etc/dns-stack/secrets/doh-dot.pem"
KEY_FILE="/etc/dns-stack/secrets/doh-dot.key"
ACME_HOME="/root/.acme.sh"
ACME_BIN="$ACME_HOME/acme.sh"
CONFIG_FILE="/etc/dns-stack/config.env"

log_info() { echo "[信息] $*"; }
log_ok()   { echo "[成功] $*"; }
log_warn() { echo "[警告] $*"; }
log_err()  { echo "[错误] $*" >&2; }

CHECK_ONLY=0
[[ "${1:-}" == "--check-only" ]] && CHECK_ONLY=1

MOSPROXY_BIN="${MOSPROXY_BIN:-/opt/dns-stack/bin/mosproxy}"
CERT_HOT_RELOAD_SINCE_PATCH=14

mosproxy_supports_cert_hot_reload() {
    local build_id="${MOSPROXY_BIN}.build-id" version
    [[ -f "$build_id" ]] || return 1
    version="$(tr -d '\r\n' < "$build_id")"
    [[ "$version" =~ -p([0-9]+)- ]] || return 1
    [[ "${BASH_REMATCH[1]}" -ge "$CERT_HOT_RELOAD_SINCE_PATCH" ]]
}

reload_mosproxy_cert() {
    if mosproxy_supports_cert_hot_reload; then
        log_ok "mosproxy 支持证书热重载，无需重启(新证书将在 10 秒内生效)"
    else
        log_info "mosproxy 二进制未含热重载补丁(p${CERT_HOT_RELOAD_SINCE_PATCH}+)，回退为重启"
        systemctl restart mosproxy.service 2>/dev/null || true
    fi
}

PANEL_CERT_DIR="/etc/dns-stack/secrets/panel"
sync_panel_cert() {
    id -u dns-stack-panel >/dev/null 2>&1 || return 0
    [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]] || return 0
    mkdir -p "$PANEL_CERT_DIR"
    install -o dns-stack-panel -g dns-stack-panel -m 0400 "$CERT_FILE" "$PANEL_CERT_DIR/cert.pem"
    install -o dns-stack-panel -g dns-stack-panel -m 0400 "$KEY_FILE"  "$PANEL_CERT_DIR/key.pem"
    chmod 0750 "$PANEL_CERT_DIR"
    chgrp dns-stack-panel "$PANEL_CERT_DIR"
    log_ok "面板证书副本已同步"
    systemctl is-active --quiet dns-stack-panel && systemctl restart dns-stack-panel 2>/dev/null || true
}

if [[ "${1:-}" == "--sync-panel-cert" ]]; then
    sync_panel_cert
    exit 0
fi

if [[ "${1:-}" == "--reload-mosproxy" ]]; then
    reload_mosproxy_cert
    exit 0
fi

[[ -f "$CERT_FILE" ]] || { log_err "证书文件不存在: ${CERT_FILE}"; exit 1; }

PUB_IP="$([[ -f "$CONFIG_FILE" ]] && grep -E '^PUBLIC_IPV4=' "$CONFIG_FILE" | head -1 | cut -d= -f2-)"
[[ -z "$PUB_IP" ]] && PUB_IP="$(curl -s -4 --max-time 5 https://ifconfig.me || echo "")"
[[ -z "$PUB_IP" ]] && PUB_IP="$(curl -s -4 --max-time 5 https://ip.sb || echo "")"
CERT_END=$(openssl x509 -in "$CERT_FILE" -noout -enddate 2>/dev/null \
    | sed -n '1s/^notAfter=//p')
CERT_END_EPOCH=$(date -d "$CERT_END" +%s 2>/dev/null || true)
[[ "$CERT_END_EPOCH" =~ ^[0-9]+$ ]] \
    || { log_err "证书到期时间无法解析"; exit 1; }
DAYS_LEFT=$(( (CERT_END_EPOCH - $(date +%s)) / 86400 ))

log_info "证书剩余有效期: ${DAYS_LEFT} 天"

SAN_OK=0
if [[ -n "$PUB_IP" ]] && openssl x509 -in "$CERT_FILE" -noout -text | grep -q "IP Address:${PUB_IP}"; then
    SAN_OK=1
    log_ok "SAN 包含当前公网 IP(${PUB_IP})"
else
    log_warn "SAN 不包含当前公网 IP(${PUB_IP})，可能是 IP 已变更"
fi

CERT_PUB_MD5=$(openssl x509 -in "$CERT_FILE" -noout -pubkey 2>/dev/null | openssl md5)
KEY_PUB_MD5=$(openssl ec -in "$KEY_FILE" -pubout 2>/dev/null | openssl md5)
if [[ "$CERT_PUB_MD5" == "$KEY_PUB_MD5" ]]; then
    log_ok "证书与私钥匹配"
else
    log_err "证书与私钥不匹配！"
    exit 1
fi

if [[ "$CHECK_ONLY" -eq 1 ]]; then
    exit 0
fi

if [[ "$DAYS_LEFT" -gt 3 && "$SAN_OK" -eq 1 ]]; then
    log_info "证书仍然有效(> 3天)且 SAN 正确，无需续签"
    exit 0
fi

log_info "正在续签(Let's Encrypt IP 证书为 shortlived，约6天有效期，需频繁续签)..."
if [[ ! -f "$ACME_BIN" ]]; then
    log_err "找不到 acme.sh: ${ACME_BIN}"
    exit 1
fi

if "$ACME_BIN" --home "$ACME_HOME" --renew -d "$PUB_IP" --ecc --force 2>&1; then
    RELOAD_CMD="$(readlink -f "${BASH_SOURCE[0]}") --reload-mosproxy"
    "$ACME_BIN" --home "$ACME_HOME" --install-cert -d "$PUB_IP" \
        --key-file "$KEY_FILE" \
        --fullchain-file "$CERT_FILE" \
        --reloadcmd "$RELOAD_CMD" \
        --ecc
    log_ok "续签成功"
    sync_panel_cert
else
    log_err "续签失败，继续使用旧证书"
    exit 1
fi
