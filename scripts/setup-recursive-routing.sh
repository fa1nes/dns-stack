#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C

CONFIG_FILE="${CONFIG_FILE:-/etc/dns-stack/config.env}"
STATE_DIR="${STATE_DIR:-/var/lib/dns-stack}"
NFT_TABLE="${NFT_TABLE:-dns_route}"
NFT_SET="${NFT_SET:-direct4}"
NFT_ENDPOINT_SET="${NFT_ENDPOINT_SET:-tunnel_endpoints}"
NFT_CN_AUTH_SET="${NFT_CN_AUTH_SET:-cn_authority}"
CACHED_NFT="${CACHED_NFT:-$STATE_DIR/chnroute/direct4.nft}"
TUNNEL_IF="${TUNNEL_IF:-wg0}"
TUNNEL_ADDR="${TUNNEL_ADDR:-10.100.0.2}"
ROUTE_TABLE="${ROUTE_TABLE:-100}"
FWMARK="${FWMARK:-0x1d5}"
UNBOUND_USER="${UNBOUND_USER:-unbound}"
WG_CONF="${WG_CONF:-/etc/wireguard/$TUNNEL_IF.conf}"

TUNNEL_FAIL_MODE="${TUNNEL_FAIL_MODE:-closed}"

MIN_SET_ENTRIES="${MIN_SET_ENTRIES:-1000}"

log_info() { echo "[信息] $*"; }
log_ok()   { echo "[成功] $*"; }
log_warn() { echo "[警告] $*"; }
log_err()  { echo "[错误] $*" >&2; }
die()      { log_err "$1"; exit 1; }

cfg_get() { [[ -f "$CONFIG_FILE" ]] && grep -E "^$1=" "$CONFIG_FILE" | head -1 | cut -d= -f2- || true; }
configured_mode="$(cfg_get TUNNEL_FAIL_MODE)"
[[ -n "$configured_mode" ]] && TUNNEL_FAIL_MODE="$configured_mode"

ACTION="${1:-apply}"

rule_exists() { ip rule show | grep -qF "$1"; }

set_entry_count() {
    nft list set inet "$NFT_TABLE" "$NFT_SET" 2>/dev/null \
        | tr ',' '\n' | grep -cE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true
}

in_set() { nft get element inet "$NFT_TABLE" "$NFT_SET" "{ $1 }" >/dev/null 2>&1; }

ensure_set_loaded() {
    [[ "$(set_entry_count)" -ge "$MIN_SET_ENTRIES" ]] && return 0
    if [[ -f "$CACHED_NFT" ]]; then
        log_info "集合为空，从缓存恢复：$CACHED_NFT"
        nft -f "$CACHED_NFT" && log_ok "  已恢复 $(set_entry_count) 条" && return 0
        log_warn "  缓存恢复失败"
    fi
    return 1
}

restore_cn_authority() {
    local file="$STATE_DIR/chnroute/cn-authority.txt" tmp n
    [[ -s "$file" ]] || { log_info "  无历史墙内权威记录，集合留空（等 timer 生成）"; return 0; }
    n="$(grep -cE '^[0-9]' "$file" || true)"
    [[ "${n:-0}" -gt 0 ]] || return 0

    tmp="$(mktemp)"
    {
        echo "flush set inet $NFT_TABLE $NFT_CN_AUTH_SET"
        grep -E '^[0-9]' "$file" \
            | sed "s|^|add element inet $NFT_TABLE $NFT_CN_AUTH_SET { |; s|\$| }|"
    } > "$tmp"
    if nft -f "$tmp"; then
        log_ok "  墙内权威集合已从历史记录恢复（$n 条）"
    else
        log_warn "  墙内权威集合恢复失败，集合保持为空（timer 会在 15 分钟内重建）"
    fi
    rm -f "$tmp"
}

verify_set_semantics() {
    local cn_sample foreign_sample rc=0

    cn_sample="$(cfg_get PUBLIC_IPV4)"
    foreign_sample="$(wg show "$TUNNEL_IF" endpoints 2>/dev/null \
        | awk 'NF > 1 {print $2}' | cut -d: -f1 | head -1)"

    if ! in_set "$TUNNEL_ADDR"; then
        log_err "  集合未包含私有网段（$TUNNEL_ADDR），集合内容异常"
        rc=1
    fi

    if [[ -z "$cn_sample" ]]; then
        log_warn "  config.env 未配置 PUBLIC_IPV4，跳过大陆样本校验"
    elif in_set "$cn_sample"; then
        log_ok "  本机公网 $cn_sample 在直连集合内（符合预期：大陆）"
    else
        log_err "  本机公网 $cn_sample 不在直连集合内，大陆数据疑似残缺"
        rc=1
    fi

    if [[ -z "$foreign_sample" ]]; then
        log_warn "  未取到隧道对端地址，跳过境外样本校验"
    elif in_set "$foreign_sample"; then
        log_err "  隧道对端 $foreign_sample 竟在直连集合内，集合疑似被污染"
        rc=1
    else
        log_ok "  隧道对端 $foreign_sample 不在直连集合内（符合预期：境外）"
    fi

    return "$rc"
}

show_status() {
    echo "=== WireGuard 加密路由 ==="
    wg show "$TUNNEL_IF" allowed-ips 2>&1 || echo "（$TUNNEL_IF 未启动）"
    echo
    echo "=== 策略路由规则 ==="
    ip rule show
    echo
    echo "=== 路由表 $ROUTE_TABLE ==="
    ip route show table "$ROUTE_TABLE" 2>&1 || echo "（空）"
    echo
    echo "=== 直连集合规模 ==="
    echo "$(set_entry_count) 条"
    echo
    echo "=== 分流链 ==="
    nft list chain inet "$NFT_TABLE" output 2>&1 || echo "（未安装）"
    echo
    echo "=== 抽样路由决策 ==="
    printf '  根服务器 198.41.0.4  打标后: '; ip route get 198.41.0.4 mark "$FWMARK" 2>&1 | head -1
    printf '  国内 180.76.76.76    直连:   '; ip route get 180.76.76.76 2>&1 | head -1
}

do_revert() {
    log_info "撤销递归分流配置"
    nft delete table inet "$NFT_TABLE" 2>/dev/null && log_ok "  已删除 nft 表 $NFT_TABLE" || log_info "  nft 表不存在，跳过"
    local guard
    for guard in 1 2 3 4 5 6 7 8 9 10; do
        rule_exists "lookup $ROUTE_TABLE" || break
        ip rule del lookup "$ROUTE_TABLE" 2>/dev/null || break
    done
    for guard in 1 2 3 4 5 6 7 8 9 10; do
        rule_exists "$FWMARK prohibit" || break
        ip rule del fwmark "$FWMARK" prohibit 2>/dev/null || break
    done
    if rule_exists "lookup $ROUTE_TABLE" || rule_exists "$FWMARK prohibit"; then
        log_warn "  仍有策略路由规则未能删除，请手工检查: ip rule show"
    else
        log_ok "  已删除策略路由规则"
    fi
    ip route flush table "$ROUTE_TABLE" 2>/dev/null || true
    log_ok "  已清空路由表 $ROUTE_TABLE"
    log_warn "WireGuard 的 allowed-ips 未改动（改回 /32 会切断隧道转发能力）"
    log_warn "如需完全还原：wg set $TUNNEL_IF peer <香港公钥> allowed-ips 10.100.0.3/32"
}

do_apply() {
    command -v nft >/dev/null || die "缺少 nft 命令"
    command -v wg  >/dev/null || die "缺少 wg 命令"
    ip link show "$TUNNEL_IF" >/dev/null 2>&1 || die "隧道接口 $TUNNEL_IF 不存在"
    unbound_uid="$(id -u "$UNBOUND_USER" 2>/dev/null)" || die "找不到用户 $UNBOUND_USER"

    log_info "Unbound 运行用户 $UNBOUND_USER (uid=$unbound_uid)"

    log_info "配置路由表 $ROUTE_TABLE"
    ip route replace 10.100.0.0/24 dev "$TUNNEL_IF" scope link table "$ROUTE_TABLE"
    ip route replace default dev "$TUNNEL_IF" table "$ROUTE_TABLE"

    rule_exists "from $TUNNEL_ADDR lookup $ROUTE_TABLE" \
        || ip rule add from "$TUNNEL_ADDR" lookup "$ROUTE_TABLE" priority 100
    rule_exists "fwmark $FWMARK lookup $ROUTE_TABLE" \
        || ip rule add fwmark "$FWMARK" lookup "$ROUTE_TABLE" priority 101

    if [[ "$TUNNEL_FAIL_MODE" == "closed" ]]; then
        rule_exists "fwmark $FWMARK prohibit" \
            || ip rule add fwmark "$FWMARK" prohibit priority 102
        log_ok "  隧道故障策略：closed（境外查询失败，不回落直连）"
    else
        while rule_exists "fwmark $FWMARK prohibit"; do ip rule del fwmark "$FWMARK" prohibit; done
        log_warn "  隧道故障策略：open（境外查询回落直连，期间可能拿到污染答案）"
    fi
    log_ok "  策略路由已就位"

    if [[ -f "$WG_CONF" ]]; then
        if grep -qE '^\s*AllowedIPs\s*=\s*0\.0\.0\.0/0' "$WG_CONF" \
           && ! grep -qE '^\s*Table\s*=\s*off' "$WG_CONF"; then
            log_err "$WG_CONF 有 AllowedIPs = 0.0.0.0/0 但缺少 Table = off"
            log_err "下次重启时 wg-quick 会装默认路由，把整机流量导进隧道"
            log_err "请在 [Interface] 段加一行：Table = off"
            die "拒绝继续，以免留下开机即失控的配置"
        fi
    fi

    hk_peer="$(wg show "$TUNNEL_IF" allowed-ips | awk '$2 ~ /^10\.100\.0\.3\/32$|^0\.0\.0\.0\/0$/ {print $1; exit}')"
    if [[ -z "$hk_peer" ]]; then
        log_warn "  未找到香港 peer（allowed-ips 既非 10.100.0.3/32 也非 0.0.0.0/0），跳过"
    else
        current="$(wg show "$TUNNEL_IF" allowed-ips | awk -v p="$hk_peer" '$1==p {print $2}')"
        if [[ "$current" == "0.0.0.0/0" ]]; then
            log_info "  香港 peer 的 allowed-ips 已是 0.0.0.0/0"
        else
            wg set "$TUNNEL_IF" peer "$hk_peer" allowed-ips 0.0.0.0/0
            log_ok "  香港 peer allowed-ips 放开至 0.0.0.0/0"
        fi
    fi

    ensure_set_loaded || true
    entries="$(set_entry_count)"
    if [[ "$entries" -lt "$MIN_SET_ENTRIES" ]]; then
        log_err "直连集合仅 $entries 条（要求 ≥ $MIN_SET_ENTRIES），拒绝安装分流链"
        log_err "集合过小会把国内递归查询也全导进隧道。请先执行 update-chnroute.sh"
        exit 1
    fi
    log_info "直连集合约 $entries 条，校验语义"
    verify_set_semantics || die "集合语义校验未通过，拒绝安装分流链（请先执行 update-chnroute.sh）"

    nft add table inet "$NFT_TABLE"

    nft "add set inet $NFT_TABLE $NFT_CN_AUTH_SET { type ipv4_addr; flags interval; auto-merge; }"
    restore_cn_authority

    nft "add set inet $NFT_TABLE $NFT_ENDPOINT_SET { type ipv4_addr; }"
    nft flush set inet "$NFT_TABLE" "$NFT_ENDPOINT_SET"
    endpoints="$(wg show "$TUNNEL_IF" endpoints 2>/dev/null \
        | awk 'NF > 1 {print $2}' | rev | cut -d: -f2- | rev | tr -d '[]' | sort -u | paste -sd, -)"
    if [[ -n "$endpoints" ]]; then
        nft add element inet "$NFT_TABLE" "$NFT_ENDPOINT_SET" "{ $endpoints }"
        log_info "  隧道端点保护：$endpoints"
    else
        log_warn "  未取到隧道端点地址，跳过端点保护"
    fi

    nft "add chain inet $NFT_TABLE output { type route hook output priority mangle; policy accept; }"
    nft flush chain inet "$NFT_TABLE" output

    nft add rule inet "$NFT_TABLE" output \
        meta skuid "$unbound_uid" \
        ip daddr != @"$NFT_SET" \
        ip daddr != @"$NFT_CN_AUTH_SET" \
        ip daddr != @"$NFT_ENDPOINT_SET" \
        counter meta mark set "$FWMARK"
    log_ok "  分流链已安装（正向匹配 uid=$unbound_uid）"

    nft "add chain inet $NFT_TABLE postrouting { type nat hook postrouting priority srcnat; policy accept; }"
    nft flush chain inet "$NFT_TABLE" postrouting
    nft add rule inet "$NFT_TABLE" postrouting \
        oifname "$TUNNEL_IF" meta mark "$FWMARK" counter masquerade
    log_ok "  源地址改写已安装（出隧道包 → $TUNNEL_ADDR）"

    echo
    log_ok "递归出口分流已生效"
    log_info "  大陆目标 → 直连 ens5 出网"
    log_info "  境外目标 → 隧道 $TUNNEL_IF 出网（经香港 NAT）"
    log_info "  作用范围 → 仅 $UNBOUND_USER 进程，其它流量不变"
}

case "$ACTION" in
    apply)  do_apply ;;
    revert) do_revert ;;
    status) show_status ;;
    *)      die "用法: $0 [apply|revert|status]" ;;
esac
