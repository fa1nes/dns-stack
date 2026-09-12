#!/usr/bin/env bash
set -Eeuo pipefail

CONFIG_FILE="${CONFIG_FILE:-/etc/dns-stack/config.env}"
TUNNEL_IF="${TUNNEL_IF:-wg0}"
WG_CONF="${WG_CONF:-/etc/wireguard/$TUNNEL_IF.conf}"
WG_PORT="${WG_PORT:-51820}"

C_G=$'\033[32m'; C_R=$'\033[31m'; C_Y=$'\033[33m'; C_D=$'\033[2m'; C_0=$'\033[0m'
info() { echo "${C_D}[信息]${C_0} $*"; }
ok()   { echo "${C_G}[成功]${C_0} $*"; }
warn() { echo "${C_Y}[警告]${C_0} $*"; }
die()  { echo "${C_R}[错误]${C_0} $*" >&2; exit 1; }

TARGET=""; SSH_PORT=22; SSH_IDENTITY=""; APPLY=0
CN_IP=""; HK_IP=""; HK_ENDPOINT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)     SSH_PORT="$2"; shift 2 ;;
        --identity) SSH_IDENTITY="$2"; shift 2 ;;
        --cn-ip)    CN_IP="$2"; shift 2 ;;
        --hk-ip)    HK_IP="$2"; shift 2 ;;
        --endpoint) HK_ENDPOINT="$2"; shift 2 ;;
        --apply)    APPLY=1; shift ;;
        --dry-run)  APPLY=0; shift ;;
        -*)         die "未知参数: $1" ;;
        *)          TARGET="$1"; shift ;;
    esac
done

[[ -n "$TARGET" ]] || die "用法: dns-stack wg-peer root@<HK地址> [--port 22] [--identity 私钥] [--apply]"
[[ "$EUID" -eq 0 ]] || die "需要 root：要读写 /etc/wireguard 与本机隧道"
command -v wg >/dev/null || die "缺少 wg 命令: apt-get install wireguard-tools"

cfg() { grep -E "^$1=" "$CONFIG_FILE" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"'; }
[[ -n "$CN_IP" ]] || CN_IP="$(cfg CN_SERVER_WG_IP)"
[[ -n "$HK_IP" ]] || HK_IP="$(cfg HK_DNS_WG_IP)"
[[ -n "$HK_IP" ]] || HK_IP="$(cfg FOREIGN_DNS_WG_IP)"
CN_IP="${CN_IP:-10.100.0.2}"
HK_IP="${HK_IP:-10.100.0.3}"

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -p "$SSH_PORT")
[[ -n "$SSH_IDENTITY" ]] && SSH_OPTS+=(-i "$SSH_IDENTITY")
hk() { ssh "${SSH_OPTS[@]}" "$TARGET" "$@"; }

echo "CN(本机) ${CN_IP}  ↔  HK ${HK_IP} (${TARGET})"
[[ "$APPLY" -eq 1 ]] || warn "当前是预演模式，不会改动任何一端。确认无误后加 --apply"
echo

info "[1/7] 检查 HK 可达与依赖..."
hk "command -v wg >/dev/null" || die "HK 上没有 wg 命令"
hk "command -v unbound-control >/dev/null || true" >/dev/null
ok "HK SSH 与 wireguard-tools 就绪"

info "[2/7] 取本机密钥..."
umask 077
mkdir -p /etc/wireguard
if [[ -s /etc/wireguard/cn-private.key ]]; then
    CN_PRIV="$(cat /etc/wireguard/cn-private.key)"
    ok "沿用已有私钥"
else
    [[ "$APPLY" -eq 1 ]] || { CN_PRIV="$(wg genkey)"; warn "预演：生成的是临时密钥，不落盘"; }
    if [[ "$APPLY" -eq 1 ]]; then
        CN_PRIV="$(wg genkey)"
        printf '%s\n' "$CN_PRIV" > /etc/wireguard/cn-private.key
        chmod 0600 /etc/wireguard/cn-private.key
        ok "已生成新私钥 /etc/wireguard/cn-private.key"
    fi
fi
CN_PUB="$(printf '%s' "$CN_PRIV" | wg pubkey)"
info "  本机公钥: $CN_PUB"

info "[3/7] 取 HK 的公钥与端点..."
HK_PUB="$(hk "wg show $TUNNEL_IF public-key 2>/dev/null || true" | tr -d '\r')"
if [[ -z "$HK_PUB" ]]; then
    HK_PUB="$(hk "test -s /etc/wireguard/hk-private.key && wg pubkey < /etc/wireguard/hk-private.key || true" | tr -d '\r')"
fi
[[ -n "$HK_PUB" ]] || die "取不到 HK 的 WireGuard 公钥——先确认 HK 上 $TUNNEL_IF 已配置"
if [[ -z "$HK_ENDPOINT" ]]; then
    HK_HOST="${TARGET#*@}"
    HK_LISTEN="$(hk "wg show $TUNNEL_IF listen-port 2>/dev/null || true" | tr -d '\r')"
    HK_ENDPOINT="${HK_HOST}:${HK_LISTEN:-$WG_PORT}"
fi
ok "HK 公钥 ${HK_PUB}  端点 ${HK_ENDPOINT}"

info "[4/7] 生成本机 $WG_CONF ..."
NEW_CONF="$(cat <<EOF
[Interface]
Address = ${CN_IP}/24
PrivateKey = ${CN_PRIV}
Table = off

[Peer]
PublicKey = ${HK_PUB}
Endpoint = ${HK_ENDPOINT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
)"
if [[ "$APPLY" -eq 0 ]]; then
    echo "${C_D}--- 将写入 $WG_CONF ---${C_0}"
    printf '%s\n' "$NEW_CONF" | sed 's/^PrivateKey = .*/PrivateKey = <本机私钥，不打印>/'
    echo "${C_D}--- 将在 HK 上追加的 peer ---${C_0}"
    printf '[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n' "$CN_PUB" "$CN_IP"
    echo "${C_D}--- 将在 HK 的 Unbound 放行 ---${C_0}"
    printf 'access-control: %s/32 allow\n' "$CN_IP"
    echo
    warn "预演结束，未改动任何一端。确认无误后重跑并加 --apply"
    exit 0
fi

BACKUP=""
if [[ -f "$WG_CONF" ]]; then
    BACKUP="$WG_CONF.bak.$(date +%s)"
    cp -a "$WG_CONF" "$BACKUP"
    info "  已备份原配置到 $BACKUP"
fi
printf '%s\n' "$NEW_CONF" > "$WG_CONF"
chmod 0600 "$WG_CONF"
ok "已写入 $WG_CONF"

rollback() {
    warn "正在回滚本机配置..."
    wg-quick down "$TUNNEL_IF" >/dev/null 2>&1 || true
    if [[ -n "$BACKUP" ]]; then
        cp -a "$BACKUP" "$WG_CONF"
        wg-quick up "$TUNNEL_IF" >/dev/null 2>&1 || true
        warn "已恢复到 $BACKUP"
    else
        rm -f "$WG_CONF"
        warn "已移除本次写入的 $WG_CONF"
    fi
}
trap 'rollback' ERR

info "[5/7] 在 HK 注册本机为 peer ..."
hk "wg set $TUNNEL_IF peer '$CN_PUB' allowed-ips '${CN_IP}/32'" \
    || die "HK 上 wg set 失败"
hk "test -f /etc/wireguard/$TUNNEL_IF.conf && cp -a /etc/wireguard/$TUNNEL_IF.conf /etc/wireguard/$TUNNEL_IF.conf.bak.\$(date +%s) || true"
hk "grep -q '$CN_PUB' /etc/wireguard/$TUNNEL_IF.conf 2>/dev/null || \
    printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n' '$CN_PUB' '$CN_IP' >> /etc/wireguard/$TUNNEL_IF.conf"
ok "HK 已接受本机 peer"

info "[6/7] 在 HK 的 Unbound 放行本机 ..."
HK_UNBOUND=/etc/unbound/unbound.conf.d/dns-stack.conf
if hk "test -f $HK_UNBOUND"; then
    hk "grep -q 'access-control: ${CN_IP}/32 allow' $HK_UNBOUND || \
        sed -i '0,/^\\s*access-control:/s//    access-control: ${CN_IP}\\/32 allow\\n&/' $HK_UNBOUND"
    hk "unbound-checkconf >/dev/null" || die "HK Unbound 配置校验失败，未重载"
    hk "systemctl reload unbound 2>/dev/null || rc-service unbound reload 2>/dev/null || true"
    ok "HK Unbound 已放行 ${CN_IP}/32"
else
    warn "HK 上找不到 $HK_UNBOUND，请手工确认 access-control 放行了 ${CN_IP}/32"
fi

info "[7/7] 拉起隧道并验证 ..."
wg-quick down "$TUNNEL_IF" >/dev/null 2>&1 || true
wg-quick up "$TUNNEL_IF" || die "本机隧道启动失败"

HANDSHAKE=""
for _ in $(seq 1 10); do
    HANDSHAKE="$(wg show "$TUNNEL_IF" latest-handshakes | awk '$2>0{print $2}' | head -1)"
    [[ -n "$HANDSHAKE" ]] && break
    sleep 2
done
[[ -n "$HANDSHAKE" ]] || die "20 秒内没有握手成功——检查 HK 的 ${HK_ENDPOINT} 是否可达、云安全组是否放行 UDP"
ok "握手成功"

ping -c 2 -W 3 "$HK_IP" >/dev/null 2>&1 \
    && ok "隧道内可达 ${HK_IP}" \
    || warn "ping 不通 ${HK_IP}（有些环境禁 ICMP，继续验证 DNS）"

ANSWER="$(dig +short +time=5 +tries=2 @"$HK_IP" -p 5335 www.wikipedia.org A 2>/dev/null \
          | grep -E '^[0-9]+\.' | head -1 || true)"
[[ -n "$ANSWER" ]] || die "经隧道查 HK 递归器(${HK_IP}:5335)拿不到答案——检查 HK 的 Unbound access-control"
ok "经隧道的境外递归正常: www.wikipedia.org -> $ANSWER"

trap - ERR

if [[ -w "$CONFIG_FILE" ]]; then
    for pair in "CN_SERVER_WG_IP=$CN_IP" "HK_DNS_WG_IP=$HK_IP" "FOREIGN_DNS_WG_IP=$HK_IP"; do
        key="${pair%%=*}"
        if grep -qE "^${key}=" "$CONFIG_FILE"; then
            sed -i "s|^${key}=.*|${pair}|" "$CONFIG_FILE"
        else
            printf '%s\n' "$pair" >> "$CONFIG_FILE"
        fi
    done
    ok "config.env 已更新 CN_SERVER_WG_IP / HK_DNS_WG_IP / FOREIGN_DNS_WG_IP"
fi

echo
ok "CN ↔ HK 隧道已对接完成"
echo "下一步（分流链路要重建，否则递归出口仍按旧表走）："
echo "  sudo bash /opt/dns-stack/dns-stack/scripts/setup-recursive-routing.sh"
echo "  sudo dns-stack health"
