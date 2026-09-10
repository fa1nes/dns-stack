#!/usr/bin/env bash
set -Eeuo pipefail

CONFIG_FILE=/etc/dns-stack/config.env
MOS_CONFIG=/etc/dns-stack/mosproxy/config.yaml

log_info() { echo "[信息] $*"; }
log_ok()   { echo "[成功] $*"; }
log_err()  { echo "[错误] $*" >&2; }

cfg() {
    [[ -f "$CONFIG_FILE" ]] || { echo ""; return; }
    grep -E "^$1=" "$CONFIG_FILE" 2>/dev/null | head -1 | cut -d= -f2- || true
}

emit_current() {
    local p host port hostport
    p="$(cfg DOH_PATH)"; p="${p:-/dns-query}"
    host="$(cfg PUBLIC_IPV4)"; host="${host:-<服务器IP>}"
    port="$(cfg DOH_PORT)";   port="${port:-443}"
    hostport="$host"
    [[ "$port" != "443" ]] && hostport="${host}:${port}"
    echo "DOH_PATH=${p}"
    echo "DOH_URL=https://${hostport}${p}"
    [[ "$p" == "/dns-query" ]] && echo "DOH_PATH_IS_DEFAULT=1" || echo "DOH_PATH_IS_DEFAULT=0"
}

probe_doh() {
    local path="$1" port
    port="$(cfg DOH_PORT)"; port="${port:-443}"
    "${DNS_STACK_GO_BIN:-/opt/dns-stack/bin/dns-stack-go}" doh-probe --path "$path" --port "$port" 2>/dev/null
}

apply_path() {
    local new_path="$1"

    if [[ ! "$new_path" =~ ^/[A-Za-z0-9._~/-]{1,128}$ ]]; then
        log_err "路径格式非法: ${new_path}"
        log_err "要求以 / 开头，仅含字母数字和 . _ ~ - /，长度 2~129"
        exit 1
    fi
    [[ -f "$MOS_CONFIG" ]] || { log_err "找不到 ${MOS_CONFIG}"; exit 1; }

    local n
    n="$(grep -cE '^[[:space:]]+path:[[:space:]]*"' "$MOS_CONFIG" || true)"
    if [[ "$n" != "2" ]]; then
        log_err "配置里 path 字段有 ${n} 处(预期 2 处)，已中止以免改坏配置"
        exit 1
    fi

    local backup="${MOS_CONFIG}.prev"
    cp -a "$MOS_CONFIG" "$backup"

    sed -i -E "s|^([[:space:]]+path:[[:space:]]*)\".*\"|\1\"${new_path}\"|" "$MOS_CONFIG"

    log_info "重启 mosproxy 使新路径生效..."
    if ! systemctl restart mosproxy.service; then
        log_err "mosproxy 重启失败，正在回滚配置"
        cp -a "$backup" "$MOS_CONFIG"
        systemctl restart mosproxy.service || true
        exit 1
    fi

    local i result="bad"
    for i in 1 2 3 4 5; do
        sleep 1
        result="$(probe_doh "$new_path")"
        [[ "$result" == "ok" ]] && break
    done
    if [[ "$result" != "ok" ]]; then
        log_err "新路径自验失败，正在回滚到原配置"
        cp -a "$backup" "$MOS_CONFIG"
        systemctl restart mosproxy.service || true
        exit 1
    fi

    if grep -qE '^DOH_PATH=' "$CONFIG_FILE" 2>/dev/null; then
        sed -i -E "s|^DOH_PATH=.*|DOH_PATH=${new_path}|" "$CONFIG_FILE"
    else
        echo "DOH_PATH=${new_path}" >> "$CONFIG_FILE"
    fi

    log_ok "DoH 路径已生效并自验通过"
    emit_current
    echo
    log_info "请把所有客户端(sing-box / Surge / iOS 描述文件)的 DoH 地址换成上面的 DOH_URL"
    log_info "旧地址即刻失效，未更新的客户端会解析失败"
}

case "${1:---print}" in
    --print)
        emit_current
        ;;
    --rotate)
        command -v openssl >/dev/null 2>&1 || { log_err "缺少 openssl"; exit 1; }
        apply_path "/$(openssl rand -hex 16)/dns-query"
        ;;
    --set)
        [[ -n "${2:-}" ]] || { log_err "--set 需要给出路径"; exit 1; }
        apply_path "$2"
        ;;
    *)
        log_err "未知参数: $1"
        echo "用法: $0 [--print | --rotate | --set <路径>]" >&2
        exit 1
        ;;
esac
