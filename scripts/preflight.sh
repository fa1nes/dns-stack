#!/usr/bin/env bash
set -uo pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

C_G=$'\033[32m'; C_R=$'\033[31m'; C_Y=$'\033[33m'; C_D=$'\033[2m'; C_0=$'\033[0m'
PASS=0; FAIL=0; WARN=0

ok()   { printf "  ${C_G}✓${C_0} %s\n" "$1"; PASS=$((PASS+1)); }
bad()  { printf "  ${C_R}✗${C_0} %s${C_D}%s${C_0}\n" "$1" "${2:+  → $2}"; FAIL=$((FAIL+1)); }
warn() { printf "  ${C_Y}!${C_0} %s${C_D}%s${C_0}\n" "$1" "${2:+  → $2}"; WARN=$((WARN+1)); }
sec()  { printf "\n${C_D}── %s ${C_0}\n" "$1"; }

CONFIG_FILE=/etc/dns-stack/config.env
STATE_DIR=/var/lib/dns-stack
ROLE="$(grep -E '^ROLE=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2- || echo unknown)"
LAST_BUNDLE_MODE=standard
if [[ -r "$STATE_DIR/sync-state/last-bundle-mode" ]]; then
    IFS= read -r LAST_BUNDLE_MODE < "$STATE_DIR/sync-state/last-bundle-mode" || true
    LAST_BUNDLE_MODE=${LAST_BUNDLE_MODE:-standard}
fi

echo "dns-stack 投产校验 · 角色: ${ROLE} · $(date '+%Y-%m-%d %H:%M:%S')"

sec "服务与定时任务"
if [[ "$ROLE" == "cn-resolver" ]]; then
    UNITS=(mosproxy unbound dns-stack-recursive-routing dns-stack-helper dns-stack-panel)
    TIMERS=(dns-stack-sync-rules.timer dns-stack-collect-polluted.timer
            dns-stack-chnroute.timer dns-stack-cn-authority.timer
            dns-stack-ecs-zone.timer dns-stack-geoip.timer
            dns-stack-renew-cert.timer dns-stack-backup.timer)
else
    UNITS=(unbound dns-stack-helper)
    TIMERS=(dns-stack-reference-data.timer
            dns-stack-classify.timer
            dns-stack-verify.timer dns-stack-backup.timer)
fi
for u in "${UNITS[@]}"; do
    if systemctl is-active --quiet "$u"; then ok "$u 运行中"; else bad "$u 未运行" "systemctl status $u"; fi
done
for t in "${TIMERS[@]}"; do
    if systemctl is-enabled --quiet "$t" 2>/dev/null; then ok "$t 已启用"; else warn "$t 未启用"; fi
done

if [[ -d /var/backups/dns-stack ]]; then
    NEWEST_BACKUP="$(find /var/backups/dns-stack -maxdepth 1 -name '*.tar.zst*' -type f \
                     -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)"
    if [[ -n "$NEWEST_BACKUP" ]]; then
        AGE_H=$(( ($(date +%s) - $(stat -c %Y "$NEWEST_BACKUP")) / 3600 ))
        if [[ "$AGE_H" -le 48 ]]; then
            ok "最近一次备份在 ${AGE_H} 小时前"
        else
            warn "最近一次备份已是 ${AGE_H} 小时前" "检查: systemctl status dns-stack-backup.service"
        fi
    else
        warn "没有任何备份文件" "手动跑一次: sudo dns-stack backup"
    fi
fi

sec "DNS 解析能力"
if dig @127.0.0.1 -p 5335 example.com A +time=8 +tries=1 +short >/dev/null 2>&1; then
    ok "Unbound 本地递归正常"
else
    bad "Unbound 递归失败" "journalctl -u unbound"
fi

if [[ "$ROLE" == "cn-resolver" ]]; then
    DOH_PATH_CUR="$(grep -E '^DOH_PATH=' "$CONFIG_FILE" 2>/dev/null | head -1 | cut -d= -f2-)"
    DOH_PATH_CUR="${DOH_PATH_CUR:-/dns-query}"
    DOH_PORT_CUR="$(grep -E '^DOH_PORT=' "$CONFIG_FILE" 2>/dev/null | head -1 | cut -d= -f2-)"
    DOH_PORT_CUR="${DOH_PORT_CUR:-443}"

    probe() {
        "${DNS_STACK_GO_BIN:-/opt/dns-stack/bin/dns-stack-go}" doh-probe --name "$1" --path "$DOH_PATH_CUR" --port "$DOH_PORT_CUR" 2>/dev/null
    }
    [[ "$(probe www.taobao.com)" == "ok" ]] && ok "DoH 入口(${DOH_PORT_CUR})响应正常" || bad "DoH 入口无响应" "检查证书与 mosproxy"

    DOT_PORT_CUR="$(grep -E '^DOT_PORT=' "$CONFIG_FILE" 2>/dev/null | head -1 | cut -d= -f2-)"
    DOT_PORT_CUR="${DOT_PORT_CUR:-853}"
    DOT_TLS="$(timeout 8 openssl s_client -connect "127.0.0.1:${DOT_PORT_CUR}" \
               -showcerts </dev/null 2>&1 || true)"
    if grep -qE 'BEGIN CERTIFICATE|Protocol[[:space:]]*:' <<<"$DOT_TLS"; then
        ok "DoT 入口(${DOT_PORT_CUR}/TCP) TLS 握手正常"
    else
        bad "DoT 入口无响应" "检查 mosproxy dot-in 配置与 TCP ${DOT_PORT_CUR}"
    fi

    if ss -ulnH "sport = :${DOT_PORT_CUR}" 2>/dev/null | grep -q .; then
        ok "DoQ 入口(${DOT_PORT_CUR}/UDP)正在监听"
    else
        warn "DoQ 入口(${DOT_PORT_CUR}/UDP)未监听" "不需要 DoQ 可忽略；需要则查 mosproxy doq-in"
    fi

    if [[ "$DOH_PATH_CUR" == "/dns-query" ]]; then
        warn "DoH 仍在默认路径 /dns-query，等于对外开放公共解析器(改: sudo dns-stack doh-path --rotate)"
    else
        ok "DoH 已启用私密路径"
    fi

    in_direct_set() { nft get element inet dns_route direct4 "{ $1 }" >/dev/null 2>&1; }
    first_a() { dig @127.0.0.1 -p "${UNBOUND_PORT:-5335}" "$1" A +short +time=8 +tries=1 2>/dev/null \
                | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1; }

    CN_IP="$(first_a www.baidu.com)"
    if [[ -z "$CN_IP" ]]; then
        bad "国内域名解析失败" "检查 unbound 与 direct4 集合"
    elif in_direct_set "$CN_IP"; then
        ok "国内域名解析到大陆节点($CN_IP)"
    else
        warn "国内域名解析到非大陆节点($CN_IP)，可能处于冷启动窗口" \
             "稍后重试；持续出现则检查 dns-stack-cn-authority.timer"
    fi

    FG_IP="$(first_a www.wikipedia.org)"
    FG_HK="$(dig @10.100.0.3 -p "${UNBOUND_PORT:-5335}" www.wikipedia.org A +short +time=8 +tries=1 2>/dev/null \
             | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)"
    if [[ -z "$FG_IP" ]]; then
        bad "境外域名解析失败" "依次检查 wg0 隧道 / 分流链 / 香港 NAT"
    elif [[ -z "$FG_HK" ]]; then
        warn "无法从香港递归器取得对照答案，跳过污染比对" "检查 10.100.0.3:5335 可达性"
    elif in_direct_set "$FG_IP"; then
        bad "境外域名解析到大陆 IP($FG_IP)，疑似污染" "检查分流链是否把该查询误判为直连"
    else
        ok "境外域名解析正常($FG_IP，香港视角 $FG_HK)"
    fi

fi

if [[ "$ROLE" == "cn-resolver" ]]; then
sec "数据采集"
EV=$(sqlite3 "$STATE_DIR/collector.db" "SELECT COUNT(*) FROM query_events;" 2>/dev/null || echo 0)
[[ "${EV:-0}" -gt 0 ]] && ok "查询事件已入库(${EV} 条)" || bad "collector 未采集到数据" "检查 mosproxy 管道"

LAT=$(sqlite3 "$STATE_DIR/collector.db" "SELECT COUNT(*) FROM query_events WHERE elapsed_ms IS NOT NULL;" 2>/dev/null || echo 0)
if [[ "${LAT:-0}" -gt 0 ]]; then ok "单次查询耗时已采集(${LAT} 条)"
else warn "无耗时数据" "可能跑的是上游原版 mosproxy"; fi

DOMS=$(sqlite3 "$STATE_DIR/collector.db" "SELECT COUNT(*) FROM domains;" 2>/dev/null || echo 0)
[[ "${DOMS:-0}" -gt 0 ]] && ok "域名聚合表正常(${DOMS} 个)" || warn "域名聚合表为空"

sec "分流规则"
count_rules() { grep -vcE '^[[:space:]]*(#|$)' "$1" 2>/dev/null || true; }
for f in cn.txt gfw.txt manual-cn.txt manual-gfw.txt cn-ip-cidr.txt polluted-ip-cidr.txt; do
    if [[ -f "$STATE_DIR/$f" ]]; then
        n=$(count_rules "$STATE_DIR/$f"); n=${n:-0}
        ok "$f 已就位(${n} 条)"
    else
        [[ "$f" == manual-*.txt ]] && warn "$f 不存在" || bad "$f 缺失" "动态分流或 mosproxy 规则加载会失败"
    fi
done
CN_CIDR_COUNT=$(count_rules "$STATE_DIR/cn-ip-cidr.txt"); CN_CIDR_COUNT=${CN_CIDR_COUNT:-0}
if [[ "$CN_CIDR_COUNT" -gt 0 ]]; then
    warn "发现旧 cn-ip-cidr.txt 附属数据(${CN_CIDR_COUNT} 条)" \
        "当前 DNS 路由不会读取该文件；可在确认下游用途后单独清理"
else
    ok "cn-ip-cidr.txt 为空（不影响域名递归）"
fi
MP_LOG=$(journalctl -u mosproxy --since "10 min ago" --no-pager 2>/dev/null || true)
if grep -qE '"domain_set".*failed to load|failed to load.*domain_set' <<<"$MP_LOG"; then
    bad "mosproxy 加载域名表报错" "journalctl -u mosproxy | grep domain_set"
else
    ok "域名表加载无报错"
fi
MP_FATAL=$(grep -oE '"level":"fatal"[^}]*"error":"[^"]{0,120}' <<<"$MP_LOG" | tail -1)
if [[ -n "$MP_FATAL" ]]; then
    if systemctl is-active --quiet mosproxy; then
        warn "mosproxy 近 10 分钟有致命错误(现已恢复)" "${MP_FATAL##*\"error\":\"}"
    else
        bad "mosproxy 存在致命错误且未在运行" "${MP_FATAL##*\"error\":\"}"
    fi
else
    ok "mosproxy 无致命错误"
fi
POLL=$(count_rules "$STATE_DIR/polluted-ip-cidr.txt"); POLL=${POLL:-0}
[[ "$POLL" -gt 0 ]] && ok "污染 IPv4/IPv6 CIDR 列表(${POLL} 个)" || warn "污染 CIDR 列表为空" "dns-stack collect-polluted"

sec "管理面板"
PANEL_RAW=$(grep -E '^PANEL_LISTEN=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2- | tr -d '[:space:]')
PANEL_RAW=${PANEL_RAW:-127.0.0.1:8080}
PANEL_PORT_N=${PANEL_RAW##*:}
[[ "$PANEL_PORT_N" =~ ^[0-9]+$ ]] || PANEL_PORT_N=8080
case "$PANEL_RAW" in
    127.*|localhost*|"[::1]"*) PANEL_BASE="http://127.0.0.1:${PANEL_PORT_N}"; PANEL_PUB=0; PANEL_MODE="本机 HTTP" ;;
    *)                          PANEL_BASE="https://127.0.0.1:${PANEL_PORT_N}"; PANEL_PUB=1; PANEL_MODE="公网 HTTPS" ;;
esac
if curl -sk -o /dev/null --max-time 8 "${PANEL_BASE}/api/health" 2>/dev/null; then
    ok "面板健康检查通过(${PANEL_MODE})"
    for ep in overview queries rules services; do
        code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 "${PANEL_BASE}/api/${ep}" 2>/dev/null)
        case "$code" in
            200)     ok "API /${ep} 可用" ;;
            401|403) ok "API /${ep} 已被认证保护(${code})" ;;
            *)       bad "API /${ep} 异常" "HTTP ${code:-无响应}" ;;
        esac
    done
else
    bad "面板无响应" "journalctl -u dns-stack-panel"
fi
fi

sec "安全边界"
if [[ "$ROLE" == "cn-resolver" ]]; then
    LISTEN=$(ss -lnt 2>/dev/null || true)
    if [[ "${PANEL_PUB:-0}" -eq 1 ]]; then
        ok "面板对公网开放(HTTPS + 密码，见下方核验)"
    elif grep -q "127.0.0.1:${PANEL_PORT_N}" <<<"$LISTEN"; then
        ok "面板仅监听回环"
    elif grep -q ":${PANEL_PORT_N}" <<<"$LISTEN"; then
        bad "面板监听了非回环地址却未启用公网模式" "确认 PANEL_LISTEN 配置"
    fi
    if [[ "${PANEL_PUB:-0}" -eq 1 ]]; then
        [[ -f /etc/dns-stack/secrets/panel/auth.json ]]             && ok "面板已设置访问密码" || bad "面板对公网开放但未设密码" "sudo dns-stack panel-password"
        UNAUTH=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "${PANEL_BASE}/api/overview" 2>/dev/null)
        [[ "$UNAUTH" == "401" || "$UNAUTH" == "403" ]]             && ok "未登录请求被拒绝(${UNAUTH})" || bad "未登录竟能访问数据接口" "HTTP ${UNAUTH}"
    fi
    PU=$(ps -eo user,args 2>/dev/null | grep "[u]vicorn app:app" | awk '{print $1}' | head -1)
    [[ -n "$PU" && "$PU" != "root" ]] && ok "面板以非 root 运行(${PU})" || bad "面板未以非 root 运行"
    grep -q "127.0.0.1:8888" <<<"$LISTEN" && ok "mosproxy 管理接口仅回环" || warn "mosproxy 管理接口监听范围异常"
fi
SEC_MODE=$(stat -c %a /etc/dns-stack/secrets 2>/dev/null)
case "$SEC_MODE" in
    700) ok "secrets 目录权限 0700" ;;
    710) ok "secrets 目录权限 0710(仅允许面板用户穿越)" ;;
    *)   bad "secrets 目录权限过宽" "当前 ${SEC_MODE:-未知}，应为 0700 或 0710" ;;
esac
if [[ -d /etc/dns-stack/secrets/panel ]]; then
    BADPERM=$(find /etc/dns-stack/secrets/panel -type f ! -perm 0400 2>/dev/null | head -3)
    [[ -z "$BADPERM" ]] && ok "面板私有证书/密码文件权限 0400"         || bad "面板私有文件权限过宽" "$BADPERM"
    if runuser -u dns-stack-panel -- cat /etc/dns-stack/secrets/doh-dot.key >/dev/null 2>&1; then
        bad "面板用户能读原始 TLS 私钥" "应仅能读 secrets/panel/ 下的副本"
    else
        ok "面板用户读不到原始私钥与备份密钥"
    fi
fi
S=$(stat -c %a /run/dns-stack/helper.sock 2>/dev/null)
[[ "$S" == "660" ]] && ok "helper socket 权限 0660" || warn "helper socket 权限=${S:-不存在}"
if [[ "$ROLE" == "cn-resolver" ]]; then
    ok "本机无本地过滤防火墙(边界防护由云安全组负责)"
    warn "请确认云安全组已放行 DoH/DoT 入口" \
        "TCP 80(ACME HTTP-01)、TCP+UDP ${DOH_PORT_CUR}(DoH/DoH3)、TCP+UDP ${DOT_PORT_CUR}(DoT/DoQ)"
fi

if [[ -S /run/dns-stack/helper.sock ]]; then
    LEAK=$("${DNS_STACK_GO_BIN:-/opt/dns-stack/bin/dns-stack-go}" helper-probe 2>/dev/null || echo -1)
    if [[ "$LEAK" == "0" ]]; then ok "日志脱敏有效(无完整客户端 IP)"
    elif [[ "$LEAK" == "-1" ]]; then warn "脱敏检查未能执行"
    else warn "日志中发现 ${LEAK} 个完整 IPv4" "多为服务器自身地址，请人工确认"; fi
fi

sec "运维与恢复能力"
command -v dns-stack >/dev/null && ok "dns-stack 命令可用" || bad "dns-stack 命令缺失"
B=$(find /var/backups/dns-stack -maxdepth 1 -type f -name '*.tar.zst*' 2>/dev/null \
    | grep -vc '\.sha256$' || true)
B=${B:-0}
[[ "${B:-0}" -gt 0 ]] && ok "存在备份包(${B} 个)" || warn "没有任何备份" "sudo dns-stack backup"
if [[ "$ROLE" == "cn-resolver" ]]; then
    RB=$(ls -1 "$STATE_DIR/rule-history"/cn-*.txt 2>/dev/null | wc -l)
    [[ "${RB:-0}" -gt 0 ]] && ok "规则可回滚(${RB} 个历史版本)" || warn "无规则历史版本"
    if [[ -f /etc/dns-stack/secrets/doh-dot.pem ]]; then
        END=$(openssl x509 -in /etc/dns-stack/secrets/doh-dot.pem -noout -enddate 2>/dev/null \
            | sed -n '1s/^notAfter=//p')
        END_EPOCH=$(date -d "$END" +%s 2>/dev/null || true)
        if [[ "$END_EPOCH" =~ ^[0-9]+$ ]]; then
            LEFT=$(( (END_EPOCH - $(date +%s)) / 86400 ))
            if   [[ "$LEFT" -gt 3 ]]; then ok "TLS 证书剩余 ${LEFT} 天"
            elif [[ "$LEFT" -gt 0 ]]; then warn "TLS 证书仅剩 ${LEFT} 天" "确认续签 timer 正常"
            else bad "TLS 证书已过期" "sudo dns-stack cert-renew"; fi
        else
            bad "TLS 证书到期时间无法解析" "openssl x509 -in /etc/dns-stack/secrets/doh-dot.pem -noout -enddate"
        fi
    else
        bad "TLS 证书缺失"
    fi
fi

sec "故障隔离(最关键)"
if [[ "$ROLE" != "cn-resolver" ]]; then
    ok "本角色不承担对外解析，无此风险"
fi
if [[ "$ROLE" == "cn-resolver" ]]; then
    MP=$(systemctl show mosproxy -p ExecStart --value 2>/dev/null)
    if grep -q "collector" <<<"$MP"; then
        ok "collector 在 mosproxy 管道下游(日志不落盘)"
    else
        warn "未检测到 collector 管道" "查询日志可能未被采集"
    fi
    grep -q "ReadWritePaths" <(systemctl cat dns-stack-panel 2>/dev/null) \
        && ok "面板有文件系统访问限制" || warn "面板缺少 ReadWritePaths 限制"
    ok "面板为只读消费方(挂掉不影响解析)"
fi

sec "连接跟踪水位"
if [[ "$ROLE" == "cn-resolver" ]]; then
    CT_MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo 0)
    CT_CUR=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo -1)
    if [[ "$CT_CUR" -lt 0 || "$CT_MAX" -le 0 ]]; then
        warn "读不到 conntrack 计数" "内核未加载 nf_conntrack 或无 /proc 访问权"
    else
        CT_PCT=$(( CT_CUR * 100 / CT_MAX ))
        if   [[ "$CT_PCT" -ge 80 ]]; then
            bad "conntrack 水位 ${CT_PCT}% (${CT_CUR}/${CT_MAX})" \
                "接近表满，满了就静默丢包；先查 nf_conntrack_tcp_timeout_established 再考虑放大 max"
        elif [[ "$CT_PCT" -ge 60 ]]; then
            warn "conntrack 水位 ${CT_PCT}% (${CT_CUR}/${CT_MAX})" "留意增长趋势"
        else
            ok "conntrack 水位 ${CT_PCT}% (${CT_CUR}/${CT_MAX})"
        fi
    fi

    CT_TCP=$(cat /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established 2>/dev/null || echo 0)
    if   [[ "$CT_TCP" -le 0 ]];      then warn "读不到 TCP established 超时"
    elif [[ "$CT_TCP" -gt 86400 ]];  then
        warn "TCP established 超时 ${CT_TCP}s(内核默认 5 天)" \
             "异常断开的 DoH/DoT 连接会长期占用表项，见 docs/sysctl-cn.conf"
    else
        ok "TCP established 超时已收紧(${CT_TCP}s)"
    fi

    CT_DROP=$(dmesg 2>/dev/null | grep -c 'nf_conntrack: table full' || true)
    if [[ "${CT_DROP:-0}" -gt 0 ]]; then
        bad "dmesg 中有 ${CT_DROP} 条 conntrack 表满记录" "已经发生过静默丢包"
    else
        ok "无 conntrack 表满记录"
    fi
fi

sec "IP 归属库(展示用)"
GEO_ASN="$STATE_DIR/geoip/GeoLite2-ASN.mmdb"
if [[ -r "$GEO_ASN" ]]; then
    GEO_AGE=$(( ( $(date +%s) - $(stat -c %Y "$GEO_ASN" 2>/dev/null || echo 0) ) / 86400 ))
    if [[ "$GEO_AGE" -gt 60 ]]; then
        warn "ASN 归属库已 ${GEO_AGE} 天未更新" "检查 dns-stack-geoip.timer"
    else
        ok "ASN 归属库就绪(${GEO_AGE} 天前更新)"
    fi
    [[ -r "$STATE_DIR/geoip/GeoLite2-City.mmdb" ]] \
        && ok "City 库就绪(省份标注可用)" \
        || warn "City 库缺失" "运营商识别不受影响，省份标注会减少"
else
    warn "未安装 ASN 归属库" "面板与 dns-stack test 不显示运营商；跑 scripts/update-geoip.sh"
fi

echo
printf "结果: ${C_G}%d 通过${C_0}  ${C_Y}%d 警告${C_0}  ${C_R}%d 失败${C_0}\n" "$PASS" "$WARN" "$FAIL"
if   [[ "$FAIL" -gt 0 ]]; then echo "存在失败项，请先处理再投入使用。"; exit 1
elif [[ "$WARN" -gt 0 ]]; then echo "无失败项，警告为可接受或待办事项。"; exit 2
else echo "全部检查通过。"; exit 0; fi
