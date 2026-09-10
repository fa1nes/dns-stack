#!/usr/bin/env bash
set -uo pipefail
export LC_ALL=C

R="@127.0.0.1 -p 5335"
SET="inet dns_route cn_authority"
TARGETS="88.221.81.192 23.62.52.96 184.26.160.65 193.108.88.128 2.16.130.65 23.61.199.64 52.76.85.180 95.101.36.65 96.7.49.67 184.26.161.192 205.251.199.15 95.101.36.192 95.100.173.192 95.100.168.65 193.108.91.2 2.18.24.164 95.101.36.128"
PROBE_DOMAINS="www.apple.com.cn www.icloud.com.cn www.lenovo.com.cn support.lenovo.com.cn"

CN_PREFIX='^(1|14|27|36|39|42|58|59|60|61|101|103|106|110|111|112|113|114|115|116|117|118|119|120|121|122|123|124|125|139|140|150|153|171|175|180|182|183|202|203|210|211|218|219|220|221|222|223)\.'
AKAMAI_PREFIX='^(2|23|88|95|96|104|184|193|205)\.'

restored=0
restore() {
    [[ $restored == 1 ]] && return
    restored=1
    echo
    echo "=== 恢复 nft 集合 ==="
    ok=0
    for ip in $TARGETS; do
        nft add element $SET "{ $ip }" 2>/dev/null && ok=$((ok + 1))
    done
    echo "已加回 $ok / $(echo $TARGETS | wc -w)"
    echo "整体重建（保险）: systemctl start dns-stack-cn-authority.service"
    systemctl start dns-stack-cn-authority.service 2>/dev/null \
        && echo "已触发集合整体重建" || echo "重建触发失败，请手动执行上面的命令"
}
trap restore EXIT INT TERM

flush_chain() {
    for z in akamaiedge.net edgekey.net aaplimg.com akadns.net lxdns.com \
             apple.com.cn icloud.com.cn lenovo.com.cn mzstatic.com; do
        unbound-control flush_zone "$z" >/dev/null 2>&1 || true
    done
    sleep 2
}

classify() {
    local ip="$1"
    if [[ "$ip" =~ $CN_PREFIX ]]; then echo "国内"
    elif [[ "$ip" =~ $AKAMAI_PREFIX ]]; then echo "境外"
    else echo "其它"; fi
}

probe() {
    local label="$1"
    echo "--- $label ---"
    for d in $PROBE_DOMAINS; do
        local ips first verdict
        ips="$(dig $R "$d" A +short +time=10 +tries=2 2>/dev/null \
               | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -3)"
        if [[ -z "$ips" ]]; then
            printf "  %-24s %s\n" "$d" "<无 A 记录>"
            continue
        fi
        first="$(echo "$ips" | head -1)"
        verdict="$(classify "$first")"
        printf "  %-24s [%s] %s\n" "$d" "$verdict" "$(echo $ips | tr '\n' ' ')"
    done
}

echo "=== 备份 ==="
nft list set $SET > /tmp/cnauth-backup.nft 2>&1
echo "集合元素数: $(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' /tmp/cnauth-backup.nft | wc -l)"
echo "待移除目标: $(echo $TARGETS | wc -w) 个"

echo
echo "=== 阶段 A: 基线 ==="
flush_chain
probe "共享 anycast 在直连集合中"

echo
echo "=== 阶段 B: 移除全部共享 anycast (v4) ==="
removed=0
for ip in $TARGETS; do
    nft delete element $SET "{ $ip }" 2>/dev/null && removed=$((removed + 1))
done
still=0
for ip in $TARGETS; do
    nft get element $SET "{ $ip }" >/dev/null 2>&1 && still=$((still + 1))
done
echo "删除成功 $removed，删除后仍命中集合 $still 个（应为 0）"

echo
flush_chain
probe "共享 anycast 已排除"
