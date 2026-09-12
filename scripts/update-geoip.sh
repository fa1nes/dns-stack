#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C

CONFIG_FILE="${CONFIG_FILE:-/etc/dns-stack/config.env}"
STATE_DIR="${STATE_DIR:-/var/lib/dns-stack}"
GEOIP_DIR="$STATE_DIR/geoip"
TUNNEL_IF="${TUNNEL_IF:-wg0}"

ASN_URL="${GEOIP_ASN_URL:-https://cdn.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@download/GeoLite2-ASN.mmdb}"
CITY_URL="${GEOIP_CITY_URL:-https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb}"
CNIP_URL="${GEOIP_CNIP_URL:-https://github.com/nmgliangwei/qqwry.ipdb/releases/latest/download/qqwry.ipdb}"

ASN_MIN_BYTES="${GEOIP_ASN_MIN_BYTES:-3000000}"
CITY_MIN_BYTES="${GEOIP_CITY_MIN_BYTES:-20000000}"
CNIP_MIN_BYTES="${GEOIP_CNIP_MIN_BYTES:-20000000}"
CROSS_MIN_BYTES="${GEOIP_CROSS_MIN_BYTES:-3000000}"

WANT_CITY="${GEOIP_ENABLE_CITY:-0}"

log_info() { echo "[信息] $*"; }
log_ok()   { echo "[成功] $*"; }
log_warn() { echo "[警告] $*"; }
log_err()  { echo "[错误] $*" >&2; }
die()      { log_err "$1"; exit 1; }

cfg_get() {
    [[ -f "$CONFIG_FILE" ]] || return 0
    grep -E "^$1=" "$CONFIG_FILE" | head -1 | cut -d= -f2- || true
}
configured_city="$(cfg_get GEOIP_ENABLE_CITY)"
[[ "$configured_city" =~ ^[01]$ ]] && WANT_CITY="$configured_city"

RELEASE_REPO="${GEOIP_RELEASE_REPO:-$(cfg_get GEOIP_RELEASE_REPO)}"
[[ -z "$RELEASE_REPO" ]] && RELEASE_REPO="$(cfg_get GITHUB_REPOSITORY)"
RELEASE_BASE="${GEOIP_RELEASE_BASE:-$(cfg_get GEOIP_RELEASE_BASE)}"
if [[ -z "$RELEASE_BASE" && -n "$RELEASE_REPO" ]]; then
    RELEASE_BASE="https://github.com/${RELEASE_REPO}/releases/download/geoip-latest"
fi
DBIP_ASN_URL="${GEOIP_DBIP_ASN_URL:-${RELEASE_BASE:+$RELEASE_BASE/dbip-asn.mmdb}}"
DBIP_CITY_URL="${GEOIP_DBIP_CITY_URL:-${RELEASE_BASE:+$RELEASE_BASE/dbip-city.mmdb}}"
IPINFO_URL="${GEOIP_IPINFO_URL:-${RELEASE_BASE:+$RELEASE_BASE/ipinfo-lite.mmdb}}"

for var in ASN CITY CNIP DBIP_ASN DBIP_CITY IPINFO; do
    val="$(cfg_get "GEOIP_${var}_URL")"
    [[ -n "$val" ]] && printf -v "${var}_URL" '%s' "$val"
done

command -v curl >/dev/null || die "缺少 curl"
DNS_STACK_BIN="${DNS_STACK_BIN:-/opt/dns-stack/bin/dns-stack-go}"
[[ -x "$DNS_STACK_BIN" ]] || die "缺少 Go 二进制 $DNS_STACK_BIN，需要它校验归属库完整性"

mkdir -p "$GEOIP_DIR"
TMP_FILE=""
cleanup() {
    [[ -n "$TMP_FILE" && -f "$TMP_FILE" ]] && rm -f "$TMP_FILE"
    return 0
}
trap cleanup EXIT

fetch_db() {
    local kind="$1" url="$2" dest="$3" min_bytes="$4"
    local name; name="$(basename "$dest")"

    TMP_FILE="$(mktemp "$GEOIP_DIR/.${kind}.XXXXXX")"

    local etag_file="$GEOIP_DIR/.${kind}.etag" cond=()
    [[ -s "$etag_file" && -f "$dest" ]] && cond=(--etag-compare "$etag_file")
    cond+=(--etag-save "$etag_file")

    log_info "检查 $name"
    if ! curl -fsSL --max-time 400 --connect-timeout 10 \
              --speed-limit 8192 --speed-time 20 \
              "${cond[@]}" -o "$TMP_FILE" "$url"; then
        log_warn "直连下载失败，改经 $TUNNEL_IF 隧道重试"
        if ! curl --interface "$TUNNEL_IF" -fsSL --max-time 400 "${cond[@]}" -o "$TMP_FILE" "$url"; then
            log_warn "$name 下载失败，保留现有库不变"
            rm -f "$TMP_FILE"; TMP_FILE=""
            return 1
        fi
    fi

    if [[ -f "$dest" && ! -s "$TMP_FILE" ]]; then
        log_info "$name 已是最新，跳过"
        rm -f "$TMP_FILE"; TMP_FILE=""
        return 2
    fi

    local size; size="$(stat -c %s "$TMP_FILE" 2>/dev/null || echo 0)"
    if [[ "$size" -lt "$min_bytes" ]]; then
        log_warn "$name 仅 $size 字节（下限 $min_bytes），判定为残缺下载，保留现有库不变"
        rm -f "$TMP_FILE"; TMP_FILE=""
        return 1
    fi

    if ! "$DNS_STACK_BIN" geoip-verify --kind "$kind" --file "$TMP_FILE"
    then
        log_warn "$name 完整性校验未通过，保留现有库不变"
        rm -f "$TMP_FILE"; TMP_FILE=""
        return 1
    fi

    chmod 0644 "$TMP_FILE" "$etag_file" 2>/dev/null || true
    mv -f "$TMP_FILE" "$dest"
    TMP_FILE=""
    log_ok "$name 已更新（$((size / 1024 / 1024)) MB）"
    return 0
}

asn_ok=0
fetch_db asn "$ASN_URL" "$GEOIP_DIR/GeoLite2-ASN.mmdb" "$ASN_MIN_BYTES" && asn_ok=1

cnip_ok=0
fetch_db cnip "$CNIP_URL" "$GEOIP_DIR/qqwry.ipdb" "$CNIP_MIN_BYTES" && cnip_ok=1

city_ok=0
if [[ "$WANT_CITY" == "1" ]]; then
    fetch_db city "$CITY_URL" "$GEOIP_DIR/GeoLite2-City.mmdb" "$CITY_MIN_BYTES" && city_ok=1
fi

dbip_asn_ok=0; dbip_city_ok=0; ipinfo_ok=0
if [[ -z "$DBIP_CITY_URL" && -z "$IPINFO_URL" ]]; then
    log_warn "未配置 GEOIP_RELEASE_REPO / GITHUB_REPOSITORY，跳过 DB-IP 与 IPinfo"
    log_warn "  这两个库是多源交叉判据的第三、第四个源，缺了会退回只信 APNIC + qqwry"
else
    [[ -n "$DBIP_ASN_URL" ]] \
        && fetch_db dbip_asn "$DBIP_ASN_URL" "$GEOIP_DIR/dbip-asn.mmdb" "$CROSS_MIN_BYTES" \
        && dbip_asn_ok=1
    [[ -n "$DBIP_CITY_URL" ]] \
        && fetch_db dbip_city "$DBIP_CITY_URL" "$GEOIP_DIR/dbip-city.mmdb" "$CROSS_MIN_BYTES" \
        && dbip_city_ok=1
    [[ -n "$IPINFO_URL" ]] \
        && fetch_db ipinfo "$IPINFO_URL" "$GEOIP_DIR/ipinfo-lite.mmdb" "$CROSS_MIN_BYTES" \
        && ipinfo_ok=1
fi

updated=""
[[ "$asn_ok" == "1" ]] && updated="$updated ASN"
[[ "$cnip_ok" == "1" ]] && updated="$updated qqwry"
[[ "$city_ok" == "1" ]] && updated="$updated City"
[[ "$dbip_asn_ok" == "1" ]] && updated="$updated DB-IP-ASN"
[[ "$dbip_city_ok" == "1" ]] && updated="$updated DB-IP-Country"
[[ "$ipinfo_ok" == "1" ]] && updated="$updated IPinfo"
if [[ -f "$GEOIP_DIR/GeoLite2-ASN.mmdb" || -f "$GEOIP_DIR/qqwry.ipdb" ]]; then
    log_ok "归属库就绪（本次更新:${updated:- 无，沿用现有库}）"
else
    die "两个主库都下载失败且本地没有副本，归属展示将不可用"
fi

cross_sources=0
cross_names=""
for entry in "qqwry.ipdb:qqwry" "GeoLite2-City.mmdb:MaxMind" \
             "dbip-city.mmdb:DB-IP" "ipinfo-lite.mmdb:IPinfo"; do
    file="${entry%%:*}"; name="${entry##*:}"
    if [[ -s "$GEOIP_DIR/$file" ]]; then
        cross_sources=$((cross_sources + 1))
        cross_names="$cross_names $name"
    fi
done
if [[ "$cross_sources" -ge 2 ]]; then
    log_ok "多源交叉可用源 ${cross_sources} 个：${cross_names# }"
else
    log_warn "多源交叉可用源只有 ${cross_sources} 个（至少 2 个才能交叉验证）"
    log_warn "  direct4-audit 会 fail-open：既不否决争议权威，也不晋级 direct4 外的大陆地址"
    log_warn "  最常见原因：GEOIP_ENABLE_CITY=0 且未配置 GEOIP_RELEASE_REPO"
fi

ls -la "$GEOIP_DIR"/*.mmdb "$GEOIP_DIR"/*.ipdb 2>/dev/null || true
