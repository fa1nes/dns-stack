#!/usr/bin/env bash
set -Eeuo pipefail

STATE_DIR="${STATE_DIR:-/var/lib/dns-stack}"
OUT_FILE="$STATE_DIR/polluted-ip.txt"
SYNC_STATE_DIR="$STATE_DIR/sync-state"
REMOTE_POLLUTED_SNAPSHOT="${REMOTE_POLLUTED_SNAPSHOT:-$SYNC_STATE_DIR/polluted-ip-cidr.remote.txt}"
LOCAL_POLLUTED_CIDRS="${LOCAL_POLLUTED_CIDRS:-$SYNC_STATE_DIR/polluted-ip-cidr.local.txt}"
EVIDENCE_FILE="${EVIDENCE_FILE:-$SYNC_STATE_DIR/polluted-ip-evidence.json}"
TRUSTED_SERVER="${TRUSTED_SERVER:-10.100.0.3}"
TRUSTED_PORT="${TRUSTED_PORT:-5335}"
POLLUTED_MAX_AGE_DAYS="${POLLUTED_MAX_AGE_DAYS:-30}"
POLLUTED_MIN_OBSERVATIONS="${POLLUTED_MIN_OBSERVATIONS:-2}"

PROBE_SERVERS=(8.8.8.8 1.1.1.1 9.9.9.9 208.67.222.222 4.2.2.2 77.88.8.8)

PROBE_DOMAINS=(
    facebook.com
    twitter.com
    youtube.com
    instagram.com
    telegram.org
    whatsapp.com
    tumblr.com
    blogspot.com
)

ROUNDS="${ROUNDS:-3}"
DIG_TIMEOUT=2

log_info() { echo "[信息] $*"; }
log_ok()   { echo "[成功] $*"; }
log_warn() { echo "[警告] $*"; }

command -v dig >/dev/null 2>&1 || { echo "[错误] 需要 dig(dnsutils)" >&2; exit 1; }
mkdir -p "$STATE_DIR" "$SYNC_STATE_DIR"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
: > "$WORK/raw.txt"
NO_SAMPLE=0

write_cidr_file() {
    install -m 0644 "$WORK/cidr.txt" "$SYNC_STATE_DIR/.polluted-ip-cidr.local.txt.new"
    mv -f "$SYNC_STATE_DIR/.polluted-ip-cidr.local.txt.new" "$LOCAL_POLLUTED_CIDRS"
    chmod 0644 "$LOCAL_POLLUTED_CIDRS"
}

log_info "开始探测(${#PROBE_SERVERS[@]} 个境外 DNS × ${#PROBE_DOMAINS[@]} 个域名 × ${ROUNDS} 轮)..."

for ((r = 1; r <= ROUNDS; r++)); do
    PREFIX="zz${RANDOM}${RANDOM}"
    for srv in "${PROBE_SERVERS[@]}"; do
        for dom in "${PROBE_DOMAINS[@]}"; do
            fqdn="${PREFIX}.${dom}"
            if ! dig "@${TRUSTED_SERVER}" -p "$TRUSTED_PORT" "$fqdn" A \
                    +time="$DIG_TIMEOUT" +tries=1 +noall +comments 2>/dev/null \
                    | grep -q 'status: NXDOMAIN'; then
                continue
            fi
            for typ in A AAAA; do
                dig "@${srv}" "$fqdn" "$typ" +short +time="$DIG_TIMEOUT" +tries=1 2>/dev/null \
                  | grep -E '^([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9a-fA-F:]+)$' >> "$WORK/raw.txt" || true
            done
        done
    done
    log_info "第 ${r}/${ROUNDS} 轮完成，累计捕获 $(wc -l < "$WORK/raw.txt" 2>/dev/null || echo 0) 条应答"
done

if [[ ! -s "$WORK/raw.txt" ]]; then
    log_warn "未捕获到任何伪造应答。可能当前网络环境不存在 DNS 投毒，或探测被完全丢弃。"
    log_warn "本轮不增加地址；已有证据仅按过期时间维护。"
    NO_SAMPLE=1
fi

DNS_STACK_BIN="${DNS_STACK_BIN:-/opt/dns-stack/bin/dns-stack-go}"
[[ -x "$DNS_STACK_BIN" ]] || { echo "[错误] 缺少 Go 二进制 $DNS_STACK_BIN" >&2; exit 1; }
"$DNS_STACK_BIN" polluted-evidence     --raw "$WORK/raw.txt"     --evidence "$EVIDENCE_FILE"     --old-output "$OUT_FILE"     --active-out "$WORK/uniq.txt"     --evidence-out "$WORK/evidence.json"     --cidr-out "$WORK/cidr.txt"     --stats "$WORK/stats"     --max-age-days "$POLLUTED_MAX_AGE_DAYS"     --min-observations "$POLLUTED_MIN_OBSERVATIONS"
read -r NEW_COUNT ADDED TOTAL RAW_UNIQUE < "$WORK/stats"
mv -f "$WORK/evidence.json" "$EVIDENCE_FILE"
chmod 0644 "$EVIDENCE_FILE"

log_info "${RAW_UNIQUE} 个候选中有 ${NEW_COUNT} 个达到至少 "\
    "${POLLUTED_MIN_OBSERVATIONS} 次独立观测的门槛"

{
    echo "# GFW DNS 污染 IP 列表"
    echo "# 由 collect-polluted-ip.sh 自动采集，每行一个 IPv4 或 IPv6 地址。"
    echo "#"
    echo "# 采集方法：向境外公共 DNS 查询随机生成的、必然不存在的子域"
    echo "#           (如 zz123456.facebook.com)。真实权威 DNS 只会回 NXDOMAIN，"
    echo "#           凡是还能拿到 A 记录的，该应答必为伪造 —— 不依赖延迟阈值。"
    echo "#"
    echo "# 污染池会轮换，本文件是历次采集的累积并集，条目只增不减。"
    echo "# 最后更新: $(date '+%Y-%m-%d %H:%M:%S %z')"
    echo "# 本次新增: ${ADDED}    累计: ${TOTAL}"
    echo ""
    cat "$WORK/uniq.txt"
} > "$WORK/final.txt"

mv -f "$WORK/final.txt" "$OUT_FILE"
chmod 0644 "$OUT_FILE"

write_cidr_file

if [[ "$NO_SAMPLE" -eq 1 ]]; then
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') polluted_no_sample total=${TOTAL}" >> "$SYNC_STATE_DIR/history.log"
else
    echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') polluted_ok total=${TOTAL} added=${ADDED}" >> "$SYNC_STATE_DIR/history.log"
fi
log_ok "污染 IPv4/IPv6 本地证据已更新：本次新增 ${ADDED} 个，累计 ${TOTAL} 个 -> ${OUT_FILE} / ${LOCAL_POLLUTED_CIDRS}"
