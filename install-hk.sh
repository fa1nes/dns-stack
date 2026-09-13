#!/bin/sh
set -eu

OPT_DIR=/opt/dns-stack
STATE_DIR=/var/lib/dns-stack
CONFIG_FILE=/etc/dns-stack/config.env
SECRETS_DIR=/etc/dns-stack/secrets
CRON_FILE=/etc/crontabs/root
GO_BIN="$OPT_DIR/bin/dns-stack-go"
LOCK_FILE=/run/lock/dns-stack-classifier.lock
LOG_DIR=/var/log/dns-stack

log_info() { echo "[信息] $*"; }
log_ok()   { echo "[成功] $*"; }
log_warn() { echo "[警告] $*"; }
log_err()  { echo "[错误] $*" >&2; }

[ "$(id -u)" -eq 0 ] || { log_err "需要 root 运行"; exit 1; }

log_info "[1/5] 安装系统依赖..."
apk add -q git openssh-client flock 2>/dev/null || apk add -q git openssh-client
log_ok "git / openssh-client 就绪（分类器是静态 Go 二进制，不需要 python3/pip/venv）"

log_info "[2/5] 创建目录..."
mkdir -p "$OPT_DIR/bin" "$STATE_DIR/publish" "$STATE_DIR/git-state" \
         "$STATE_DIR/psl-data" "$STATE_DIR/chnroute" "$SECRETS_DIR" "$LOG_DIR" /run/lock
chmod 0700 "$SECRETS_DIR"

log_info "[3/5] 校验分类器二进制..."
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

log_info "[4/5] 检查配置与密钥..."
if [ ! -f "$CONFIG_FILE" ]; then
    log_warn "$CONFIG_FILE 不存在。请从旧分类节点复制后核对以下键："
    log_warn "  ROLE=global-builder / CN_SERVER_WG_IP / CN_SERVER_SSH_USER / CN_SERVER_SSH_PORT"
    log_warn "  GITHUB_REPOSITORY / GITHUB_BRANCH / HK_DNS_WG_IP(本机 10.100.0.3)"
else
    grep -q '^ROLE=global-builder' "$CONFIG_FILE" \
        || log_warn "$CONFIG_FILE 的 ROLE 不是 global-builder，请核对"
fi

PULL_KEY="$SECRETS_DIR/cn-pull-key"
if [ ! -f "$PULL_KEY" ]; then
    ssh-keygen -t ed25519 -f "$PULL_KEY" -N '' -C dns-stack-cn-pull -q
    log_warn "已生成 $PULL_KEY；请把 $PULL_KEY.pub 加到 CN 的 /root/.ssh/authorized_keys："
    log_warn "  command=\"/opt/dns-stack/bin/dns-stack-go collect pull-batch\",no-agent-forwarding,no-X11-forwarding,no-port-forwarding,no-pty <公钥整行>"
fi
chmod 0600 "$PULL_KEY" 2>/dev/null || true

[ -f "$SECRETS_DIR/github_deploy_key" ] || {
    log_warn "缺少 $SECRETS_DIR/github_deploy_key——从旧分类节点复制(GitHub 仓库的 deploy key)"
    log_warn "  没有它 publish 无法 push，规则就不会传到国内服务器"
}

log_info "[5/5] 写入 cron 调度..."
touch "$CRON_FILE"
sed -i '/# dns-stack-classifier begin/,/# dns-stack-classifier end/d' "$CRON_FILE"
cat >> "$CRON_FILE" <<EOF
# dns-stack-classifier begin
*/5 * * * * flock -n $LOCK_FILE $GO_BIN classify pipeline --authority-every 6h >>$LOG_DIR/pipeline.log 2>&1
*/30 * * * * flock -n $LOCK_FILE $GO_BIN classify verify-rules >>$LOG_DIR/verify.log 2>&1
23 3 * * * flock -n $LOCK_FILE $GO_BIN classify update-reference-data >>$LOG_DIR/reference-data.log 2>&1
# 7 */6 * * * flock -n $LOCK_FILE $GO_BIN classify publish >>$LOG_DIR/publish.log 2>&1
# dns-stack-classifier end
EOF
rc-service crond status >/dev/null 2>&1 || rc-service crond start
rc-update add crond default >/dev/null 2>&1 || true
log_ok "cron 调度已写入 $CRON_FILE"

if dig +short +time=3 +tries=1 @127.0.0.1 -p 5335 www.aliyun.com A 2>/dev/null | grep -q '^[0-9]'; then
    log_ok "本机 Unbound 127.0.0.1:5335 应答正常"
else
    log_warn "本机 Unbound 5335 校验失败——境外视角与权威位置分类都依赖它"
fi

echo
log_ok "HK 规则构建节点安装完成。剩余人工步骤："
echo "  1) 从旧节点搬迁 $STATE_DIR/classifier.db(用 sqlite 在线备份，不要直接 cp 运行中的库)"
echo "     首次打开会自动迁到 schema v6：观测表并轨、去掉恒为 0 的 consec_* 与只写不读的字段"
echo "  2) 复制 config.env 与 github_deploy_key(见上面 [4/5] 的提示)"
echo "  3) 确认 CN 的 Unbound access-control 放行本机(10.100.0.3)到 5335"
echo "  4) 手工跑一轮验证: $GO_BIN classify pipeline --skip-authority"
echo "  5) 确认无误后再停用旧节点的 classify/verify/pull-candidates 等调度"
