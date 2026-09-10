#!/usr/bin/env bash
set -uo pipefail
export LC_ALL=C

RESOLVER="${RESOLVER:-127.0.0.1}"
RESOLVER_PORT="${RESOLVER_PORT:-5335}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FIXTURE="$WORK/zones.txt"
cat >"$FIXTURE" <<'EOF'
# comment line
apple.com
zzz-no-such-zone-test.invalid
akamaiedge.net
EOF

cat >"$WORK/old.sh" <<'OLDEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
RESOLVER="$1"; RESOLVER_PORT="$2"; MANUAL_ZONES="$3"; TMP_PAIRS="$4"
manual_list="$(grep -vE '^\s*(#|$)' "$MANUAL_ZONES" | tr 'A-Z' 'a-z' || true)"
for zone in $manual_list; do
    ns_list="$(dig "@$RESOLVER" -p "$RESOLVER_PORT" "$zone" NS +short +time=4 +tries=1 2>/dev/null \
               | grep -E '\.$' | head -8)"
    [[ -n "$ns_list" ]] || ns_list="$(dig "@$RESOLVER" -p "$RESOLVER_PORT" "$zone" SOA +short \
                                      +time=4 +tries=1 2>/dev/null | awk '{print $1}' | head -1)"
    for ns in $ns_list; do
        dig "@$RESOLVER" -p "$RESOLVER_PORT" "$ns" A +short +time=4 +tries=1 2>/dev/null \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
            | sed "s|^|$zone |; s|\$| 0|" >> "$TMP_PAIRS" || true
    done
done
echo "OLD-REACHED-END"
OLDEOF

cat >"$WORK/new.sh" <<'NEWEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
RESOLVER="$1"; RESOLVER_PORT="$2"; MANUAL_ZONES="$3"; TMP_PAIRS="$4"
log_info() { echo "[信息] $*"; }
log_warn() { echo "[警告] $*"; }
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
if (( manual_total > 0 )); then
    log_info "已并入人工补充区域 $manual_resolved/$manual_total 个"
fi
if [[ -n "$manual_unresolved" ]]; then
    log_warn "人工补充区域本轮取不到权威地址：${manual_unresolved# }"
fi
echo "NEW-REACHED-END"
NEWEOF

fail=0

echo "=== 对照组：旧实现（期望静默崩溃：退出码非 0 且无 OLD-REACHED-END）==="
: >"$WORK/pairs-old.txt"
old_out="$(bash "$WORK/old.sh" "$RESOLVER" "$RESOLVER_PORT" "$FIXTURE" "$WORK/pairs-old.txt" 2>&1)"
old_rc=$?
echo "$old_out"
echo "旧实现退出码=$old_rc"
if [[ "$old_rc" == 0 ]] || grep -q 'OLD-REACHED-END' <<<"$old_out"; then
    echo "✗ 阴性对照失败：旧实现没有崩溃，本测试没能触发缺陷"
    fail=1
elif [[ -n "$old_out" ]]; then
    echo "✗ 旧实现崩溃了但有输出，与生产观测到的静默失败形态不符"
    fail=1
else
    echo "✓ 阴性对照成立：旧实现零输出静默 exit $old_rc（与生产失败形态一致）"
fi

echo
echo "=== 实验组：新实现（期望不崩，报告 2/3，警告列出取不到的域名）==="
: >"$WORK/pairs-new.txt"
new_out="$(bash "$WORK/new.sh" "$RESOLVER" "$RESOLVER_PORT" "$FIXTURE" "$WORK/pairs-new.txt" 2>&1)"
new_rc=$?
echo "$new_out"
echo "新实现退出码=$new_rc"

[[ "$new_rc" == 0 ]] || { echo "✗ 新实现退出码非 0"; fail=1; }
grep -q 'NEW-REACHED-END' <<<"$new_out" || { echo "✗ 新实现未跑到结尾"; fail=1; }
grep -q '已并入人工补充区域 2/3 个' <<<"$new_out" || { echo "✗ 未报告 2/3"; fail=1; }
grep -q 'zzz-no-such-zone-test.invalid' <<<"$new_out" || { echo "✗ 未在警告中列出取不到的域名"; fail=1; }

apple_n="$(grep -c '^apple\.com ' "$WORK/pairs-new.txt" || true)"
akamai_n="$(grep -c '^akamaiedge\.net ' "$WORK/pairs-new.txt" || true)"
echo "写入记录：apple.com=$apple_n 条, akamaiedge.net=$akamai_n 条"
[[ "$apple_n" -gt 0 ]] || { echo "✗ apple.com 未写入任何权威地址"; fail=1; }
[[ "$akamai_n" -gt 0 ]] || { echo "✗ akamaiedge.net 未写入任何权威地址"; fail=1; }
[[ "$akamai_n" -le 8 ]] || { echo "✗ akamaiedge.net 超过 8 条，NR<=8 截断未生效"; fail=1; }

echo
if (( fail )); then
    echo "结果: 失败"
    exit 1
fi
echo "结果: 全部通过"
