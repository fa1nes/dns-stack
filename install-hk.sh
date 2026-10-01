#!/bin/sh
set -eu

OPT_DIR=/opt/dns-stack
STATE_DIR=/var/lib/dns-stack
CONFIG_FILE=/etc/dns-stack/config.env
GO_BIN="$OPT_DIR/bin/dns-stack-go"
CRON_FILE=/etc/crontabs/root
LOG_DIR=/var/log/dns-stack
LOG_KEEP_BYTES=2097152

log_info() { echo "[信息] $*"; }
log_ok()   { echo "[成功] $*"; }
log_warn() { echo "[警告] $*"; }
log_err()  { echo "[错误] $*" >&2; }

[ "$(id -u)" -eq 0 ] || { log_err "需要 root 运行"; exit 1; }

log_info "[1/5] 创建目录..."
mkdir -p "$OPT_DIR/bin" "$STATE_DIR" "$LOG_DIR"

log_info "[2/5] 校验二进制..."
if [ ! -x "$GO_BIN" ]; then
    log_err "缺少 $GO_BIN"
    log_err "  从 GitHub Releases 下载对应架构的 dns-stack-linux-<arch> 放到该路径并 chmod +x"
    log_err "  该二进制由 CI 以 CGO_ENABLED=0 构建，是完全静态的 ELF，不依赖 musl/glibc"
    exit 1
fi
if ! "$GO_BIN" version >/dev/null 2>&1; then
    log_err "$GO_BIN 无法执行——确认下载的架构与本机一致（uname -m: $(uname -m)）"
    exit 1
fi
log_ok "$("$GO_BIN" version)"

log_info "[3/5] 检查配置..."
mkdir -p "$(dirname "$CONFIG_FILE")"
if [ ! -f "$CONFIG_FILE" ]; then
    printf 'ROLE=offshore\nSTATE_DIR=%s\n' "$STATE_DIR" > "$CONFIG_FILE"
    chmod 0640 "$CONFIG_FILE"
    log_ok "已写入 $CONFIG_FILE (ROLE=offshore)"
elif ! grep -q '^ROLE=offshore' "$CONFIG_FILE"; then
    sed -i 's/^ROLE=.*/ROLE=offshore/' "$CONFIG_FILE"
    grep -q '^ROLE=' "$CONFIG_FILE" || printf 'ROLE=offshore\n' >> "$CONFIG_FILE"
    log_ok "$CONFIG_FILE 的 ROLE 已更新为 offshore"
fi

log_info "[4/5] 写入日志轮转调度..."
apk add -q flock 2>/dev/null || true
touch "$CRON_FILE"
sed -i '/# dns-stack begin/,/# dns-stack end/d' "$CRON_FILE"
sed -i '/# dns-stack-classifier begin/,/# dns-stack-classifier end/d' "$CRON_FILE"
TRIM_LOG="$LOG_DIR/trim-logs.log"
cat >> "$CRON_FILE" <<EOF
# dns-stack begin
41 4 * * * $GO_BIN trim-logs --drop-stale --dir $LOG_DIR --keep-bytes $LOG_KEEP_BYTES >> $TRIM_LOG 2>&1
# dns-stack end
EOF
rc-service crond status >/dev/null 2>&1 || rc-service crond start
rc-update add crond default >/dev/null 2>&1 || true
"$GO_BIN" trim-logs --drop-stale --dir "$LOG_DIR" --keep-bytes "$LOG_KEEP_BYTES" 2>&1 | tee -a "$TRIM_LOG"
log_ok "每日保留每份日志末尾 $((LOG_KEEP_BYTES/1024/1024))MB"

log_info "[5/5] 让 Unbound 不依赖开机顺序、崩溃后自动拉起..."
BOOT_CONF=/etc/unbound/unbound.conf.d/00-dns-stack-boot.conf
mkdir -p "$(dirname "$BOOT_CONF")"
printf 'server:
    ip-freebind: yes
' > "$BOOT_CONF"
if ! unbound-checkconf >/dev/null 2>&1; then
    rm -f "$BOOT_CONF"
    log_err "加入 ip-freebind 后 unbound-checkconf 不通过，已撤回 $BOOT_CONF"
    exit 1
fi
UNBOUND_RC=/etc/conf.d/unbound
touch "$UNBOUND_RC"
sed -i '/^#\{0,1\}supervisor=/d' "$UNBOUND_RC"
echo 'supervisor=supervise-daemon' >> "$UNBOUND_RC"
rc-update add unbound default >/dev/null 2>&1 || true
rc-service unbound stop >/dev/null 2>&1 || true
rc-service unbound zap >/dev/null 2>&1 || true
start-stop-daemon -K -x /usr/sbin/unbound >/dev/null 2>&1 || true
for _ in 1 2 3 4 5 6 7 8 9 10; do
    grep -qx unbound /proc/[0-9]*/comm 2>/dev/null || break
    sleep 1
done
if grep -qx unbound /proc/[0-9]*/comm 2>/dev/null; then
    log_err "旧的 Unbound 进程 10 秒内没有退出，不在它还占着端口时切换守护方式"
    exit 1
fi
rc-service unbound start
log_ok "Unbound 已改为 supervise-daemon 守护，监听隧道地址不再要求 wg0 先于它启动"

if dig +short +time=3 +tries=1 @127.0.0.1 -p 5335 www.aliyun.com A 2>/dev/null | grep -q '^[0-9]'; then
    log_ok "本机 Unbound 127.0.0.1:5335 应答正常"
else
    log_warn "本机 Unbound 5335 校验失败——国内节点的境外查询全靠它"
fi

echo
log_ok "境外递归节点安装完成。这台机器的职责只有两项："
echo "  1) 本机 Unbound 作为国内节点走隧道过来的递归出口"
echo "  2) 作为 mosproxy 的降级上游 foreign-hk (10.100.0.3:5335)"
echo "确认 CN 的 Unbound access-control 放行本机到 5335。"
