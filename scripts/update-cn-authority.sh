#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C

CONFIG_FILE="${CONFIG_FILE:-/etc/dns-stack/config.env}"
STATE_DIR="${STATE_DIR:-/var/lib/dns-stack}"
CHNROUTE_DIR="$STATE_DIR/chnroute"
DIRECT_LIST="$CHNROUTE_DIR/direct4.txt"
NFT_TABLE="${NFT_TABLE:-dns_route}"
NFT_SET="${NFT_SET:-cn_authority}"
UNBOUND_CTL="${UNBOUND_CTL:-unbound-control}"
RESOLVER="${RESOLVER:-127.0.0.1}"
RESOLVER_PORT="${RESOLVER_PORT:-5335}"
MANUAL_ZONES="${MANUAL_ZONES:-$STATE_DIR/manual-cn-zones.txt}"

AGGREGATE_PREFIX="${CN_AUTHORITY_AGGREGATE:-24}"

log_info() { echo "[信息] $*"; }
log_ok()   { echo "[成功] $*"; }
log_warn() { echo "[警告] $*"; }
log_err()  { echo "[错误] $*" >&2; }
die()      { log_err "$1"; exit 1; }

cfg_get() { [[ -f "$CONFIG_FILE" ]] && grep -E "^$1=" "$CONFIG_FILE" | head -1 | cut -d= -f2- || true; }
configured_agg="$(cfg_get CN_AUTHORITY_AGGREGATE)"
[[ "$configured_agg" =~ ^[0-9]+$ ]] && AGGREGATE_PREFIX="$configured_agg"
configured_cross_age="$(cfg_get GEO_CROSS_MAX_AGE_SEC)"
[[ "$configured_cross_age" =~ ^[0-9]+$ ]] && export GEO_CROSS_MAX_AGE_SEC="$configured_cross_age"

command -v nft >/dev/null || die "缺少 nft 命令"
command -v dig >/dev/null || die "缺少 dig 命令"

[[ -f "$DIRECT_LIST" ]] || die "缺少大陆 IP 集合 $DIRECT_LIST，请先执行 update-chnroute.sh"

mkdir -p "$CHNROUTE_DIR"
ZONES_FILE="$CHNROUTE_DIR/cn-zones.txt"
MATCHED_FILE="$CHNROUTE_DIR/cn-zones-matched.txt"
RESULT_FILE="$CHNROUTE_DIR/cn-authority.txt"

ECS_CONF_FILE="${ECS_CONF_FILE:-/etc/unbound/unbound.conf.d/dns-stack-ecs.conf}"
ECS_STATE_FILE="${ECS_STATE_FILE:-$CHNROUTE_DIR/ecs-accum-state.tsv}"
SHARED_ANYCAST_FILE="${SHARED_ANYCAST_FILE:-$CHNROUTE_DIR/shared-anycast.txt}"
SHARED_EXCLUDED_FILE="${SHARED_EXCLUDED_FILE:-$CHNROUTE_DIR/shared-excluded.txt}"
GEO_DISPUTED_FILE="${GEO_DISPUTED_FILE:-$CHNROUTE_DIR/geo-disputed.txt}"
GEO_PROMOTED_FILE="${GEO_PROMOTED_FILE:-$CHNROUTE_DIR/geo-promoted.txt}"
SHARED_EXCLUDED_OUTPUT="${SHARED_EXCLUDED_OUTPUT:-}"
SHARED_EXCLUDED_EXTERNAL=0
TMP_ZONES="$(mktemp "$CHNROUTE_DIR/.zones.XXXXXX")"
TMP_PAIRS="$(mktemp "$CHNROUTE_DIR/.pairs.XXXXXX")"
TMP_RESULT="$(mktemp "$CHNROUTE_DIR/.cnauth.XXXXXX")"
TMP_MATCHED="$(mktemp "$CHNROUTE_DIR/.matched.XXXXXX")"
TMP_NFT="$(mktemp "$CHNROUTE_DIR/.cnauth-nft.XXXXXX")"
TMP_ECS="$(mktemp "$CHNROUTE_DIR/.ecs.XXXXXX")"
TMP_SHARED_EXCLUDED=""
if [[ -n "$SHARED_EXCLUDED_OUTPUT" ]]; then
    SHARED_EXCLUDED_EXTERNAL=1
else
    TMP_SHARED_EXCLUDED="$(mktemp "$CHNROUTE_DIR/.shared-excluded.XXXXXX")"
    SHARED_EXCLUDED_OUTPUT="$TMP_SHARED_EXCLUDED"
fi
TMP_INFRA="$(mktemp "$CHNROUTE_DIR/.infra.XXXXXX")"
trap 'rm -f "$TMP_ZONES" "$TMP_PAIRS" "$TMP_RESULT" "$TMP_MATCHED" "$TMP_NFT" "$TMP_ECS" "$TMP_SHARED_EXCLUDED" "$TMP_INFRA"' EXIT

log_info "从 Unbound infra cache 发现候选区域"
$UNBOUND_CTL dump_infra 2>/dev/null > "$TMP_INFRA" || true

awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $2 ~ /\.$/ {print $2}' "$TMP_INFRA" \
    | sed 's/\.$//' | tr 'A-Z' 'a-z' | sed '/^$/d' | sort -u > "$TMP_ZONES" || true

zone_count="$(wc -l < "$TMP_ZONES")"
log_info "候选区域 $zone_count 个（含公共后缀与保留域，判定段会剔除）"
[[ "$zone_count" -gt 0 ]] || { log_warn "没有候选区域（Unbound 可能刚启动），本次不改动集合"; exit 0; }

log_info "从 infra cache 收集权威地址"
awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $2 ~ /\.$/ && $2 != "." {
        rto = -1
        for (i = 3; i < NF; i++) if ($i == "rto") { rto = $(i+1); break }
        sub(/\.$/, "", $2)
        print tolower($2), $1, rto
    }' "$TMP_INFRA" | sort -u > "$TMP_PAIRS" || true

if [[ -f "$MANUAL_ZONES" ]]; then
    manual_list="$(grep -vE '^\s*(#|$)' "$MANUAL_ZONES" | tr 'A-Z' 'a-z' || true)"
    manual_total=0
    manual_resolved=0
    manual_unresolved=""
    for zone in $manual_list; do
        manual_total=$((manual_total + 1))
        ns_list="$(dig "@$RESOLVER" -p "$RESOLVER_PORT" "$zone" NS +short +time=4 +tries=1 2>/dev/null \
                   | grep -E '\.$' | awk 'NR<=8' || true)"
        if [[ -z "$ns_list" ]]; then
            ns_list="$(dig "@$RESOLVER" -p "$RESOLVER_PORT" "$zone" SOA +short +time=4 +tries=1 2>/dev/null \
                       | awk 'NR==1 && NF {print $1}' || true)"
        fi
        if [[ -z "$ns_list" ]]; then
            manual_unresolved="$manual_unresolved $zone"
            continue
        fi
        zone_hit=0
        for ns in $ns_list; do
            addr_list="$(dig "@$RESOLVER" -p "$RESOLVER_PORT" "$ns" A +short +time=4 +tries=1 2>/dev/null \
                         | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)"
            [[ -n "$addr_list" ]] || continue
            printf '%s\n' "$addr_list" | sed "s|^|$zone |; s|\$| 0|" >> "$TMP_PAIRS"
            zone_hit=1
        done
        if (( zone_hit )); then
            manual_resolved=$((manual_resolved + 1))
        else
            manual_unresolved="$manual_unresolved $zone"
        fi
    done
    sort -u -o "$TMP_PAIRS" "$TMP_PAIRS"
    if (( manual_total > 0 )); then
        log_info "已并入人工补充区域 $manual_resolved/$manual_total 个"
    fi
    if [[ -n "$manual_unresolved" ]]; then
        log_warn "人工补充区域本轮取不到权威地址：${manual_unresolved# }"
        log_warn "  这些域名本轮不进直连集合，解析会走隧道；下一轮 timer 重试"
    fi
fi

pair_count="$(wc -l < "$TMP_PAIRS")"
log_info "收集到 $pair_count 条 (区域, 权威地址) 记录"

DNS_STACK_BIN="${DNS_STACK_BIN:-/opt/dns-stack/bin/dns-stack-go}"
[[ -x "$DNS_STACK_BIN" ]] || die "缺少 Go 二进制 $DNS_STACK_BIN"

SHARED_EXCLUDED_OUTPUT="$SHARED_EXCLUDED_OUTPUT" PSL_FILE="${PSL_FILE:-}" "$DNS_STACK_BIN" cn-authority     --state "$STATE_DIR"     --pairs "$TMP_PAIRS"     --direct4 "$DIRECT_LIST"     --manual "$MANUAL_ZONES"     --shared "$SHARED_ANYCAST_FILE"     --disputed "$GEO_DISPUTED_FILE"     --promoted "$GEO_PROMOTED_FILE"     --out "$TMP_RESULT"     --matched "$TMP_MATCHED"     --ecs-out "$TMP_ECS"     --ecs-prev "$ECS_CONF_FILE"     --ecs-state "$ECS_STATE_FILE"     --shared-excluded-out "$SHARED_EXCLUDED_OUTPUT"     --aggregate "$AGGREGATE_PREFIX" || die "cn-authority 计算失败"

GUARD_MIN_RATIO="${GUARD_MIN_RATIO:-40}"   # 新结果不得低于旧结果的这个百分比
FORCE=0
[[ "${1:-}" == "--force" ]] && FORCE=1

new_count="$(grep -cE '^[0-9]' "$TMP_RESULT" 2>/dev/null || true)"; new_count="${new_count:-0}"
old_count="$(grep -cE '^[0-9]' "$RESULT_FILE" 2>/dev/null || true)"; old_count="${old_count:-0}"

if [[ "$FORCE" -eq 0 && "$old_count" -ge 20 ]]; then
    threshold=$(( old_count * GUARD_MIN_RATIO / 100 ))
    if [[ "$new_count" -lt "$threshold" ]]; then
        log_err "墙内权威网段从 $old_count 条骤降到 $new_count 条（低于 ${GUARD_MIN_RATIO}% 阈值 $threshold），拒绝写入"
        log_err "  最可能的原因：Unbound 的 infra cache 刚被清空（flush_infra / 重启），"
        log_err "  本轮只看得到最近几分钟查过的权威。等 15 分钟后 timer 自然重跑即可恢复。"
        log_err "  确认要覆盖请用: $0 --force"
        exit 1
    fi
fi

{
    echo "add table inet $NFT_TABLE"
    echo "add set inet $NFT_TABLE $NFT_SET { type ipv4_addr; flags interval; auto-merge; }"
    echo "flush set inet $NFT_TABLE $NFT_SET"
    if [[ -s "$TMP_RESULT" ]]; then
        paste -sd, - < "$TMP_RESULT" | tr ',' '\n' | split -l 500 --filter='
            printf "add element inet '"$NFT_TABLE"' '"$NFT_SET"' { "
            paste -sd, -
            printf " }\n"
        '
    fi
} > "$TMP_NFT"

nft -f "$TMP_NFT" || die "nft 加载失败，集合保持加载前状态（事务已回滚）"

chmod 0644 "$TMP_ZONES" "$TMP_RESULT" "$TMP_MATCHED"
mv -f "$TMP_ZONES" "$ZONES_FILE"; TMP_ZONES=""
mv -f "$TMP_RESULT" "$RESULT_FILE"; TMP_RESULT=""
mv -f "$TMP_MATCHED" "$MATCHED_FILE"; TMP_MATCHED=""
if [[ "$SHARED_EXCLUDED_EXTERNAL" -eq 0 ]]; then
    chmod 0644 "$TMP_SHARED_EXCLUDED"
    mv -f "$TMP_SHARED_EXCLUDED" "$SHARED_EXCLUDED_FILE"
    TMP_SHARED_EXCLUDED=""
fi

log_ok "墙内权威集合已更新：$(wc -l < "$RESULT_FILE") 条网段"
log_info "结果文件：$RESULT_FILE"
log_info "墙内区域清单：$MATCHED_FILE（$(wc -l < "$MATCHED_FILE") 个）"
log_info "人工补充区域可写入：$MANUAL_ZONES"

ecs_new="$(grep -c '^\s*send-client-subnet:' "$TMP_ECS" 2>/dev/null || true)"; ecs_new="${ecs_new:-0}"
ecs_old="$(grep -c '^\s*send-client-subnet:' "$ECS_CONF_FILE" 2>/dev/null || true)"; ecs_old="${ecs_old:-0}"

if [[ "$ecs_new" -eq 0 ]]; then
    log_warn "ECS 白名单为空，保留现有的 $ecs_old 条不动"
    log_warn "  空白名单会让所有权威都收不到客户端子网，国内 CDN 调度会静默退化。"
elif [[ "$FORCE" -eq 0 && "$ecs_old" -ge 20 && "$ecs_new" -lt $(( ecs_old * GUARD_MIN_RATIO / 100 )) ]]; then
    log_warn "ECS 白名单从 $ecs_old 条骤降到 $ecs_new 条，保留现有内容（--force 可覆盖）"
elif cmp -s "$TMP_ECS" "$ECS_CONF_FILE" 2>/dev/null; then
    log_info "ECS 白名单无变化（$ecs_new 条），跳过重载"
else
    ecs_stage="${ECS_CONF_FILE}.stage.$$"
    cp "$TMP_ECS" "$ecs_stage"
    chmod 0644 "$ecs_stage"
    if ! unbound-checkconf >/dev/null 2>&1; then
        log_warn "现网 unbound 配置本身就没通过 checkconf，跳过 ECS 白名单更新"
        rm -f "$ecs_stage"
    else
        ecs_backup="${ECS_CONF_FILE}.prev"
        if [[ -f "$ECS_CONF_FILE" ]]; then
            cp -a "$ECS_CONF_FILE" "$ecs_backup"
        fi
        mv -f "$ecs_stage" "$ECS_CONF_FILE"
        if unbound-checkconf >/dev/null 2>&1; then
            if unbound-control reload_keep_cache >/dev/null 2>&1; then
                log_ok "ECS 白名单已更新：$ecs_old -> $ecs_new 条（已热重载，缓存保留）"
            else
                log_warn "ECS 白名单已写入（$ecs_new 条）但热重载失败，下次重启生效"
            fi
        else
            if [[ -f "$ecs_backup" ]]; then
                mv -f "$ecs_backup" "$ECS_CONF_FILE"
            else
                rm -f "$ECS_CONF_FILE"
            fi
            log_err "新的 ECS 白名单没通过 unbound-checkconf，已回滚"
        fi
    fi
fi
rm -f "$TMP_ECS"
