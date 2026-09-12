#!/usr/bin/env bash
set -uo pipefail
export LC_ALL=C

DOMAIN="${1:-}"
SUBNET="${2:-}"
[[ -n "$DOMAIN" ]] || { echo "用法: $0 <域名> [客户端子网，如 192.0.2.0/24]" >&2; exit 2; }
[[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "域名格式非法" >&2; exit 2; }
if [[ -n "$SUBNET" ]]; then
    [[ "$SUBNET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] \
        || { echo "子网格式应为 a.b.c.0/24" >&2; exit 2; }
fi

RESOLVER="${RESOLVER:-127.0.0.1}"
PORT="${PORT:-5335}"
RULES_DIR="${RULES_DIR:-/var/lib/dns-stack}"
GO_BIN="${DNS_STACK_GO_BIN:-/opt/dns-stack/bin/dns-stack-go}"
ECS_CONF="${ECS_CONF:-/etc/unbound/unbound.conf.d/dns-stack-ecs.conf}"

C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_DIM=$'\033[2m'; C_RST=$'\033[0m'
ok()   { printf '  %s✓%s %s\n' "$C_OK" "$C_RST" "$*"; }
warn() { printf '  %s!%s %s\n' "$C_WARN" "$C_RST" "$*"; }
bad()  { printf '  %s✗%s %s\n' "$C_ERR" "$C_RST" "$*"; }
dim()  { printf '    %s%s%s\n' "$C_DIM" "$*" "$C_RST"; }
head_() { printf '\n%s\n' "── $* ─────────────────────────────"; }

geo() {
    [[ -n "${1:-}" ]] || return 0
    [[ -x "$GO_BIN" ]] || return 0
    "$GO_BIN" geoip-check "$1" 2>/dev/null | cut -f2
}

in_cidr_file() {
    local ip="$1" file="$2"
    [[ -f "$file" ]] || { echo "文件缺失"; return; }
    [[ -x "$GO_BIN" ]] || { echo ""; return; }
    printf '%s\n' "$ip" \
        | "$GO_BIN" ipset-check --list "$file" --show-match 2>/dev/null \
        | cut -f2
}

in_nft_set() {
    nft get element inet dns_route "$1" "{ $2 }" >/dev/null 2>&1 && echo yes || echo no
}

echo "域名: $DOMAIN${SUBNET:+   客户端子网: $SUBNET}"

head_ "1. 解析结果"
ecs_arg=(); [[ -n "$SUBNET" ]] && ecs_arg=(+subnet="$SUBNET")
ips="$(dig +short +time=4 +tries=1 "$DOMAIN" A "@$RESOLVER" -p "$PORT" "${ecs_arg[@]}" 2>/dev/null \
       | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)"
if [[ -z "$ips" ]]; then
    bad "没有 A 记录（可能是 CNAME 链断了或权威无应答）"
else
    while read -r ip; do
        [[ -n "$ip" ]] || continue
        printf '  %-16s %s\n' "$ip" "$(geo "$ip")"
    done <<<"$ips"
fi
first_ip="$(head -1 <<<"$ips")"

head_ "2. ECS 行为"
if [[ -n "$SUBNET" ]]; then
    a="$(dig +short +time=4 "$DOMAIN" A "@$RESOLVER" -p "$PORT" 2>/dev/null \
         | grep -E '^[0-9.]+$' | sort | tr '\n' ' ')"
    b="$(dig +short +time=4 "$DOMAIN" A "@$RESOLVER" -p "$PORT" +subnet="$SUBNET" 2>/dev/null \
         | grep -E '^[0-9.]+$' | sort | tr '\n' ' ')"
    if [[ "$a" == "$b" ]]; then
        ok "带与不带 ECS 结果一致（权威未按客户端位置调度，或未收到 ECS）"
    else
        warn "带 ECS 后答案不同 —— 权威确实收到了客户端位置"
        dim "无ECS  : $a"
        dim "带ECS  : $b"
        dim "境外服务出现这种分歧时要警惕：可能拿到"给中国用户"的地址"
    fi
fi
scope="$(dig "$DOMAIN" A "@$RESOLVER" -p "$PORT" ${SUBNET:++subnet=$SUBNET} 2>/dev/null \
         | grep -i 'CLIENT-SUBNET' | head -1 || true)"
[[ -n "$scope" ]] && dim "权威回的 scope: ${scope#*: }"

head_ "3. 权威与递归走向"
zone="$(awk -F. '{ if (NF>=2) print $(NF-1)"."$NF; else print $0 }' <<<"$DOMAIN")"
for ns in $(dig +short +time=4 "$zone" NS "@$RESOLVER" -p "$PORT" 2>/dev/null | head -4); do
    nsip="$(dig +short +time=3 "${ns%.}" A "@$RESOLVER" -p "$PORT" 2>/dev/null \
            | grep -E '^[0-9.]+$' | head -1)"
    [[ -n "$nsip" ]] || continue
    if [[ "$(in_nft_set direct4 "$nsip")" == yes ]]; then
        route="大陆 -> 直连"
    elif [[ "$(in_nft_set cn_authority "$nsip")" == yes ]]; then
        route="属墙内域名 -> 直连"
    else
        route="境外 -> 经隧道"
    fi
    ecs_wl=no
    if [[ -f "$ECS_CONF" && -x "$GO_BIN" ]]; then
        [[ "$(printf '%s\n' "$nsip" \
              | "$GO_BIN" ipset-check --ecs-conf "$ECS_CONF" 2>/dev/null \
              | cut -f2)" == "1" ]] && ecs_wl=yes
    fi
    printf '  %-28s %-16s %-20s ECS白名单=%s\n' "${ns%.}" "$nsip" "$route" "$ecs_wl"
done

head_ "4. 客户端分流规则"
match_suffix() {
    local f="$RULES_DIR/$1" d="$DOMAIN"
    [[ -f "$f" ]] || { echo "(文件缺失)"; return; }
    while [[ -n "$d" ]]; do
        if grep -qxF "$d" "$f" 2>/dev/null; then echo "$d"; return; fi
        d="${d#*.}"; [[ "$d" == *.* ]] || { grep -qxF "$d" "$f" 2>/dev/null && echo "$d"; break; }
    done
    echo ""
}
cn_hit="$(match_suffix cn.txt)"
gfw_hit="$(match_suffix gfw.txt)"
[[ -n "$cn_hit" ]] && warn "cn.txt 命中 $cn_hit（客户端会直连）" || ok "cn.txt 未命中"
[[ -n "$gfw_hit" ]] && ok "gfw.txt 命中 $gfw_hit（客户端走代理）" || warn "gfw.txt 未命中"
if [[ -z "$cn_hit" && -z "$gfw_hit" ]]; then
    dim "两份域名规则都没收录 —— 客户端只能按 IP 判断，或落到默认出站"
fi
if [[ -n "$first_ip" ]]; then
    hit="$(in_cidr_file "$first_ip" "$RULES_DIR/cn-ip-cidr.txt")"
    [[ -n "$hit" ]] && warn "cn-ip-cidr 命中 $hit（按 IP 会直连）" || ok "cn-ip-cidr 未命中"
    hit="$(in_cidr_file "$first_ip" "$RULES_DIR/polluted-ip-cidr.txt")"
    if [[ -n "$hit" ]]; then
        bad "polluted-ip-cidr 命中 $hit —— 客户端会**丢弃**这个地址，直接表现为打不开"
    else
        ok "polluted-ip-cidr 未命中"
    fi
fi

head_ "5. ECH"
https_rr="$(dig +short +time=4 "$DOMAIN" HTTPS "@$RESOLVER" -p "$PORT" 2>/dev/null | head -1 || true)"
if [[ -z "$https_rr" ]]; then
    ok "无 HTTPS 记录，不涉及 ECH"
elif grep -q 'ech=' <<<"$https_rr"; then
    warn "Unbound 侧仍带 ech（正常，剥离在 mosproxy 层）"
    dim "客户端实际是否拿到 ech，看指标 ech_stripped_total 是否在涨"
else
    ok "HTTPS 记录不含 ech"
fi

head_ "6. 可达性（仅供参考，非用户视角）"
if [[ -n "$first_ip" ]]; then
    code="$(curl -s -m 12 -o /dev/null -w '%{http_code}' "https://$DOMAIN/" 2>/dev/null || echo 000)"
    if [[ "$code" == "000" ]]; then
        bad "本机 HTTPS 请求失败（超时或被重置）"
    else
        ok "本机 HTTPS 返回 $code"
    fi
    dim "服务器线路与主人不同，此项仅作线索"
fi
echo
