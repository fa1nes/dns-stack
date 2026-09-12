#!/usr/bin/env bash
set -Eeuo pipefail

export LC_ALL=C

CONFIG_FILE="${CONFIG_FILE:-/etc/dns-stack/config.env}"
STATE_DIR="${STATE_DIR:-/var/lib/dns-stack}"
CHNROUTE_DIR="$STATE_DIR/chnroute"
APNIC_URL="${APNIC_URL:-https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest}"
CNIP_DB="${CNIP_DB:-$STATE_DIR/geoip/qqwry.ipdb}"
[[ -f "$CNIP_DB" ]] || CNIP_DB=""
NFT_TABLE="${NFT_TABLE:-dns_route}"
NFT_SET="${NFT_SET:-direct4}"
TUNNEL_IF="${TUNNEL_IF:-wg0}"

MIN_ENTRIES="${CHNROUTE_MIN_ENTRIES:-5000}"

MIN_ADDRESSES="${CHNROUTE_MIN_ADDRESSES:-200000000}"

log_info() { echo "[信息] $*"; }
log_ok()   { echo "[成功] $*"; }
log_warn() { echo "[警告] $*"; }
log_err()  { echo "[错误] $*" >&2; }
die()      { log_err "$1"; exit 1; }

cfg_get() { [[ -f "$CONFIG_FILE" ]] && grep -E "^$1=" "$CONFIG_FILE" | head -1 | cut -d= -f2- || true; }
configured_min="$(cfg_get CHNROUTE_MIN_ENTRIES)"
[[ "$configured_min" =~ ^[0-9]+$ ]] && MIN_ENTRIES="$configured_min"
configured_min_addr="$(cfg_get CHNROUTE_MIN_ADDRESSES)"
[[ "$configured_min_addr" =~ ^[0-9]+$ ]] && MIN_ADDRESSES="$configured_min_addr"

command -v nft >/dev/null || die "缺少 nft 命令，本脚本要求 nftables（Debian 12 默认）"

mkdir -p "$CHNROUTE_DIR"
RAW="$CHNROUTE_DIR/delegated-apnic-latest.txt"
CIDR_LIST="$CHNROUTE_DIR/direct4.txt"
NFT_SCRIPT="$CHNROUTE_DIR/direct4.nft"
TMP_RAW="$(mktemp "$CHNROUTE_DIR/.raw.XXXXXX")"
TMP_CIDR="$(mktemp "$CHNROUTE_DIR/.cidr.XXXXXX")"
TMP_NFT="$(mktemp "$CHNROUTE_DIR/.nft.XXXXXX")"
TMP_STATS="$(mktemp "$CHNROUTE_DIR/.stats.XXXXXX")"
trap 'rm -f "${TMP_RAW:-}" "${TMP_CIDR:-}" "${TMP_NFT:-}" "${TMP_STATS:-}"' EXIT

log_info "拉取 APNIC 委派记录（经 $TUNNEL_IF 隧道）"
if ! curl --interface "$TUNNEL_IF" -fsS --max-time 120 -o "$TMP_RAW" "$APNIC_URL"; then
    log_warn "经隧道拉取失败，改为直连重试（会明显更慢）"
    curl -fsS --max-time 600 -o "$TMP_RAW" "$APNIC_URL" \
        || die "APNIC 拉取失败，保留现有集合不变"
fi

raw_cn_lines="$(grep -c '|CN|ipv4|' "$TMP_RAW" || true)"
log_info "APNIC 原始 CN IPv4 记录：$raw_cn_lines 条"
[[ "$raw_cn_lines" -ge "$MIN_ENTRIES" ]] \
    || die "CN 记录仅 $raw_cn_lines 条，低于护栏阈值 $MIN_ENTRIES，判定为残缺数据，保留现有集合不变"

log_info "转换为 CIDR 并合并保留网段"
DNS_STACK_BIN="${DNS_STACK_BIN:-/opt/dns-stack/bin/dns-stack-go}"
[[ -x "$DNS_STACK_BIN" ]] || die "缺少 Go 二进制 $DNS_STACK_BIN"
"$DNS_STACK_BIN" chnroute     --apnic "$TMP_RAW"     --cnip "$CNIP_DB"     --out "$TMP_CIDR"     --excluded-out "$CHNROUTE_DIR/direct4-excluded.txt"     --stats "$TMP_STATS" || die "chnroute 计算失败，保留现有集合不变"

source "$TMP_STATS"
[[ "${CN_ADDRESSES:-0}" -ge "$MIN_ADDRESSES" ]] \
    || die "大陆覆盖地址仅 ${CN_ADDRESSES:-0} 个，低于护栏阈值 $MIN_ADDRESSES，判定为数据异常，保留现有集合不变"
cidr_count="$NETWORKS"

{
    echo "add table inet $NFT_TABLE"
    echo "add set inet $NFT_TABLE $NFT_SET { type ipv4_addr; flags interval; auto-merge; }"
    echo "flush set inet $NFT_TABLE $NFT_SET"
    paste -sd, - < "$TMP_CIDR" | tr ',' '\n' | split -l 1000 --filter='
        printf "add element inet '"$NFT_TABLE"' '"$NFT_SET"' { "
        paste -sd, -
        printf " }\n"
    '
} > "$TMP_NFT"

log_info "加载 nftables 集合（原子事务）"
nft -f "$TMP_NFT" || die "nft 加载失败，集合保持加载前状态（事务已回滚）"

loaded="$(nft list set inet "$NFT_TABLE" "$NFT_SET" 2>/dev/null | grep -c '/' || true)"

chmod 0644 "$TMP_RAW" "$TMP_CIDR" "$TMP_NFT"
mv -f "$TMP_RAW" "$RAW"
mv -f "$TMP_CIDR" "$CIDR_LIST"
mv -f "$TMP_NFT" "$NFT_SCRIPT"
TMP_RAW=""; TMP_CIDR=""; TMP_NFT=""

log_ok "直连集合已更新：$cidr_count 条网段（源 $raw_cn_lines 条 APNIC 记录）"
log_info "集合文件：$CIDR_LIST"
log_info "nft 脚本：$NFT_SCRIPT"
