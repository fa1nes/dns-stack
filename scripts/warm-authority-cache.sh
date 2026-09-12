#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C

DB="${COLLECTOR_DB:-/var/lib/dns-stack/collector.db}"
RESOLVER="${RESOLVER:-127.0.0.1}"
RESOLVER_PORT="${RESOLVER_PORT:-5335}"
TOP_N="${WARM_TOP_N:-400}"
PARALLEL="${WARM_PARALLEL:-8}"
WARM_SUCCESS_WINDOW="${WARM_SUCCESS_WINDOW:-604800}"
WARM_PER_ZONE="${WARM_PER_ZONE:-3}"

command -v dig >/dev/null || { echo "[错误] 缺少 dig" >&2; exit 1; }
command -v sqlite3 >/dev/null || { echo "[错误] 缺少 sqlite3" >&2; exit 1; }
[[ -f "$DB" ]] || { echo "[错误] 查询库不存在: $DB" >&2; exit 1; }

now="$(date +%s)"
since=$(( now - WARM_SUCCESS_WINDOW ))

domains="$(sqlite3 "$DB" "
    SELECT d.domain FROM domains d
    WHERE EXISTS (SELECT 1 FROM query_events e
                  WHERE e.domain = d.domain AND e.rcode = 0 AND e.ts >= ${since})
    ORDER BY d.occurrence_count DESC LIMIT ${TOP_N};" 2>/dev/null || true)"

count="$(printf '%s\n' "$domains" | grep -c . || true)"; count="${count:-0}"
if [[ "$count" -eq 0 ]]; then
    total="$(sqlite3 "$DB" "SELECT COUNT(*) FROM domains;" 2>/dev/null || true)"
    total="${total:-0}"
    if [[ "$total" -eq 0 ]]; then
        echo "[警告] 查询库里没有域名记录，本次不预热（collector 可能刚部署）"
    else
        echo "[警告] $total 个域名中，近 $((WARM_SUCCESS_WINDOW / 86400)) 天内没有任何一个解析成功过。"
        echo "[警告]   这不是预热的问题——递归链路本身可能已经坏了，先查 unbound 与隧道。"
    fi
    exit 0
fi

domains="$(printf '%s\n' "$domains" | awk -F. -v n="$WARM_PER_ZONE" '
    NF >= 2 { key = $(NF-1) "." $NF } NF < 2 { key = $0 }
    { if (++seen[key] <= n) print }')"
kept="$(printf '%s\n' "$domains" | grep -c . || true)"; kept="${kept:-0}"

echo "[信息] 预热 $kept 个域名的权威（并发 $PARALLEL；"
echo "[信息]   候选 $count 个 → 同注册域限 $WARM_PER_ZONE 个后剩 $kept 个；"
echo "[信息]   已排除近 $((WARM_SUCCESS_WINDOW / 86400)) 天从未成功解析过的域名）"

printf '%s\n' "$domains" | xargs -P "$PARALLEL" -I{} \
    dig +short +time=3 +tries=1 "{}" A "@${RESOLVER}" -p "${RESOLVER_PORT}" \
    >/dev/null 2>&1 || true

if command -v unbound-control >/dev/null 2>&1; then
    zones="$(unbound-control dump_infra 2>/dev/null \
             | awk '$1 ~ /^[0-9.]+$/ && $2 ~ /\.$/ {print $2}' | sort -u | wc -l || true)"
    echo "[成功] 预热完成，infra cache 现有 ${zones:-?} 个区域"
else
    echo "[成功] 预热完成"
fi
