#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C

NFT_TABLE="${NFT_TABLE:-dns_route}"
NFT_SET="${NFT_SET:-direct4}"
FWMARK="${FWMARK:-0x1d5}"
UNIT="${UNIT:-dns-stack-recursive-routing.service}"
STATE_DIR="${STATE_DIR:-/var/lib/dns-stack}"
MIN_SET_ENTRIES="${MIN_SET_ENTRIES:-1000}"

CN_AUTH_SET="${CN_AUTH_SET:-cn_authority}"
CN_AUTH_FILE="${CN_AUTH_FILE:-$STATE_DIR/chnroute/cn-authority.txt}"
CN_AUTH_MIN_RATIO="${CN_AUTH_MIN_RATIO:-40}"

FAIL_STATE="$STATE_DIR/routing-watchdog.fail"
MAX_CONSECUTIVE_REPAIRS="${MAX_CONSECUTIVE_REPAIRS:-5}"

log() { echo "[watchdog] $*"; }
log_err() { echo "[watchdog] $*" >&2; }

_MARK_RE="0x0*${FWMARK#0x}"

chain_healthy() {
    nft list chain inet "$NFT_TABLE" output 2>/dev/null \
        | grep -qE "meta mark set ${_MARK_RE}\b"
}

nat_healthy() {
    nft list chain inet "$NFT_TABLE" postrouting 2>/dev/null \
        | grep -qE "meta mark ${_MARK_RE}\b.*masquerade"
}

rule_healthy() {
    ip rule show | grep -qE "fwmark ${_MARK_RE}\b"
}

set_healthy() {
    local n
    n="$(nft list set inet "$NFT_TABLE" "$NFT_SET" 2>/dev/null \
         | tr ',' '\n' | grep -cE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)"
    [[ "${n:-0}" -ge "$MIN_SET_ENTRIES" ]]
}

cn_authority_healthy() {
    local baseline kernel
    baseline="$(grep -cE '^[0-9]' "$CN_AUTH_FILE" 2>/dev/null || true)"
    [[ "${baseline:-0}" -ge 20 ]] || return 0

    kernel="$(nft list set inet "$NFT_TABLE" "$CN_AUTH_SET" 2>/dev/null \
              | tr ',' '\n' | grep -cE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)"
    [[ "${kernel:-0}" -ge $(( baseline * CN_AUTH_MIN_RATIO / 100 )) ]]
}

tunnel_up() { ip link show wg0 >/dev/null 2>&1; }

diagnose() {
    local problems=()
    chain_healthy        || problems+=("分流链缺失或无打标规则")
    nat_healthy          || problems+=("NAT 源地址改写链缺失")
    rule_healthy         || problems+=("fwmark 策略路由规则缺失")
    set_healthy          || problems+=("大陆 IP 集合过小或为空")
    cn_authority_healthy || problems+=("墙内权威集合过小或为空(国内域名会走隧道拿境外节点)")
    printf '%s\n' "${problems[@]}"
}

read_fail_count() { cat "$FAIL_STATE" 2>/dev/null || echo 0; }
write_fail_count() { echo "$1" > "$FAIL_STATE" 2>/dev/null || true; }

audit() {
    local operation="$1" ok="$2" message="$3"
    sqlite3 "$STATE_DIR/collector.db" \
        "INSERT INTO audit_log(ts, actor, operation, args, ok, message)
         VALUES ($(date +%s), 'watchdog', '$operation', '',
                 $ok, '$(echo "$message" | sed "s/'/''/g" | cut -c1-500)');" \
        2>/dev/null || true
}

flush_poisoned_cache() {
    if unbound-control -c /etc/unbound/unbound.conf flush_zone . >/dev/null 2>&1; then
        log "已清空 Unbound 缓存(故障期间可能缓存了污染答案)"
    else
        log_err "清空 Unbound 缓存失败——故障期间的污染答案可能仍在缓存中"
        log_err "  请手工执行: unbound-control flush_zone ."
    fi
}

handle_failure() {
    local problems="$1"
    local summary fails
    summary="$(echo "$problems" | paste -sd';' - | sed 's/;/; /g')"
    fails="$(read_fail_count)"

    if ! tunnel_up; then
        log "隧道 wg0 未就绪，等待 wg-quick 拉起(不计入失败次数)"
        log "  $summary"
        return 0
    fi

    if [[ "$fails" -ge "$MAX_CONSECUTIVE_REPAIRS" ]]; then
        log_err "已连续 ${fails} 次修复失败，停止自动重建，等待人工处理"
        log_err "  $summary"
        log_err "  排查: systemctl status $UNIT && journalctl -u $UNIT -n 50"
        log_err "  处理完后清零: rm -f $FAIL_STATE"
        return 1
    fi

    fails=$((fails + 1))
    write_fail_count "$fails"
    log "检测到分流异常，尝试重建(第 ${fails} 次)"
    log "  $summary"

    if ! systemctl restart "$UNIT" >/dev/null 2>&1; then
        log_err "重建命令执行失败: systemctl restart $UNIT"
        audit "routing_watchdog_repair" 0 "重建失败(第 ${fails} 次): $summary"
        return 1
    fi

    local remaining
    remaining="$(diagnose)"
    if [[ -n "$remaining" ]]; then
        log_err "重建后仍未恢复: $(echo "$remaining" | paste -sd';' - | sed 's/;/; /g')"
        audit "routing_watchdog_repair" 0 "重建后仍异常(第 ${fails} 次): $summary"
        return 1
    fi

    flush_poisoned_cache
    write_fail_count 0
    audit "routing_watchdog_repair" 1 "分流已自动重建(第 ${fails} 次尝试): $summary"
    log "分流已重建并验证通过"
    return 0
}

main() {
    command -v nft >/dev/null || { log_err "缺少 nft 命令"; exit 1; }

    local problems
    problems="$(diagnose)"

    if [[ -z "$problems" ]]; then
        if [[ "$(read_fail_count)" != "0" ]]; then
            log "分流已恢复正常"
            flush_poisoned_cache
            audit "routing_watchdog_recover" 1 "分流已恢复正常(非本看门狗重建)"
            write_fail_count 0
        fi
        exit 0
    fi

    handle_failure "$problems"
}

main "$@"
