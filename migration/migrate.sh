#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../scripts/backup-common.sh"
source "$SCRIPT_DIR/../scripts/mosproxy-artifact-common.sh"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log_step() { echo "[$1/12] $2"; }
log_ok()   { echo "  ✓ $*"; }
log_err()  { echo "  ✗ $*" >&2; }
die()      { log_err "$1"; exit 1; }

TARGET=""
SSH_PORT=22
SSH_IDENTITY=""
DRY_RUN=0

POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port) SSH_PORT="$2"; shift 2 ;;
        --identity) SSH_IDENTITY="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        *) POSITIONAL+=("$1"); shift ;;
    esac
done
TARGET="${POSITIONAL[0]:-}"
[[ -z "$TARGET" ]] && die "用法: dns-stack migrate root@新服务器IP [--port 22] [--identity 私钥路径] [--dry-run]"

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -p "$SSH_PORT")
[[ -n "$SSH_IDENTITY" ]] && SSH_OPTS+=(-i "$SSH_IDENTITY")

ssh_run() { ssh "${SSH_OPTS[@]}" "$TARGET" "$@"; }

ROLE_LOCAL="$(bc_role)"
[[ -z "$ROLE_LOCAL" || "$ROLE_LOCAL" == "unknown" ]] && \
    die "读不到本机角色(检查 $CONFIG_FILE 里的 ROLE)，无法确定目标机该装成什么角色"

log_step 1 "正在检查目标服务器连接..."
ssh_run "echo ok" >/dev/null || die "无法通过 SSH 连接到 ${TARGET}(端口 ${SSH_PORT})"
log_ok "SSH 连接正常"

log_step 2 "正在检查目标系统兼容性..."
REMOTE_OS="$(ssh_run "grep -oP '^ID=\K.*' /etc/os-release" | tr -d '"')"
REMOTE_ARCH="$(ssh_run "uname -m")"
LOCAL_ARCH="$(uname -m)"
[[ "$REMOTE_OS" =~ ^(debian|ubuntu)$ ]] || die "目标系统不是 Debian/Ubuntu(检测到: ${REMOTE_OS})"
if [[ "$REMOTE_ARCH" != "$LOCAL_ARCH" ]]; then
    log_err "架构不一致：本机 ${LOCAL_ARCH}，目标 ${REMOTE_ARCH}——数据库和二进制可能不兼容"
    [[ "$DRY_RUN" -eq 0 ]] && die "架构不兼容，中止迁移(如确认要继续，请人工介入)"
fi
log_ok "系统: ${REMOTE_OS} / 架构: ${REMOTE_ARCH}"

log_step 3 "正在检查磁盘空间..."
REMOTE_AVAIL_KB="$(ssh_run "df -Pk / | tail -1 | awk '{print \$4}'")"
[[ "${REMOTE_AVAIL_KB:-0}" -lt 2097152 ]] && die "目标服务器可用空间不足 2GB"
log_ok "目标可用空间: $((REMOTE_AVAIL_KB/1024))MB"

log_step 4 "正在检查端口占用..."
REMOTE_PORTS="$(ssh_run "ss -tlnH 2>/dev/null | awk '{print \$4}' | grep -oE '[0-9]+\$' | sort -u" || true)"
for p in 5335 8080; do
    if echo "$REMOTE_PORTS" | grep -qx "$p"; then
        log_err "目标服务器端口 ${p} 已被占用，可能与 dns-stack 冲突"
    fi
done
log_ok "端口检查完成(仅提示，不阻断)"

log_step 5 "正在检查目标是否已有 DNS Stack..."
if ssh_run "test -f /etc/dns-stack/config.env" 2>/dev/null; then
    die "目标服务器已存在 /etc/dns-stack/config.env，为避免覆盖数据，请先手动确认后再迁移"
fi
log_ok "目标是全新环境"

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo
    echo "--dry-run 模式：以上检查全部完成，不会修改目标服务器任何内容。"
    exit 0
fi

log_step 6 "正在创建旧服务器一致性备份..."
BACKUP_FILE="$(bash "$SCRIPT_DIR/../scripts/backup.sh" --include-secrets 2>&1 | tail -1)"
[[ -f "$BACKUP_FILE" ]] || die "备份失败"
log_ok "备份文件: ${BACKUP_FILE}"

log_step 7 "正在生成 age 加密迁移包..."
EXPORT_PKG="$BACKUP_FILE"
log_ok "迁移包: ${EXPORT_PKG}"

log_step 8 "正在传输迁移包与项目源码..."
for need in install.sh config.example.env systemd scripts bin cmd internal web; do
    [[ -e "$PROJECT_ROOT/$need" ]] || die \
"源码树不完整(缺 ${need}): ${PROJECT_ROOT}
   本机的源码树可能是旧版安装留下的残缺副本。
   请先在本机用完整的项目目录重跑一次 install.sh 补齐，再执行迁移。"
done
INCOMING=/root/dns-stack-migrate-incoming
ssh_run "mkdir -p $INCOMING"
scp "${SSH_OPTS[@]}" "$EXPORT_PKG" "$TARGET:$INCOMING/"
SRC_NAME="$(basename "$PROJECT_ROOT")"
tar -C "$(dirname "$PROJECT_ROOT")" -c "$SRC_NAME" | zstd -q -T0 | \
    ssh "${SSH_OPTS[@]}" "$TARGET" "zstd -d -q | tar -C $INCOMING -x"

MOSPROXY_EXPECTED="$(mosproxy_expected_version "$PROJECT_ROOT")" \
    || die "versions.lock 与 mosproxy 补丁序列不一致"
if mosproxy_artifact_matches /opt/dns-stack/bin/mosproxy "$MOSPROXY_EXPECTED"; then
    ssh_run "mkdir -p $INCOMING/$SRC_NAME/bin"
    scp "${SSH_OPTS[@]}" \
        /opt/dns-stack/bin/mosproxy \
        /opt/dns-stack/bin/mosproxy.sha256 \
        /opt/dns-stack/bin/mosproxy.build-id \
        "$TARGET:$INCOMING/$SRC_NAME/bin/"
    log_ok "已附带验证过的 mosproxy 二进制(${MOSPROXY_EXPECTED})"
elif [[ -x /opt/dns-stack/bin/mosproxy ]]; then
    log_err "当前 mosproxy 不含补丁指纹 ${MOSPROXY_EXPECTED}，未附带；目标机将使用源码包产物或现场构建"
fi
log_ok "传输完成"

log_step 9 "目标服务器安装 DNS Stack..."
ssh_run "mkdir -p /etc/dns-stack" || die "目标机创建配置目录失败"
ssh_run "test -f /etc/dns-stack/config.env" 2>/dev/null || \
    ssh_run "printf 'ROLE=%s\n' '$ROLE_LOCAL' > /etc/dns-stack/config.env"
ssh_run "chmod +x $INCOMING/$SRC_NAME/install.sh && cd $INCOMING/$SRC_NAME && bash install.sh </dev/null" \
    || die "目标机 install.sh 执行失败，请登录目标机查看输出后重试(数据尚未导入，旧机未受影响)"
log_ok "目标服务器环境安装完成"

log_step 10 "在目标服务器导入数据..."
ssh_run "dns-stack verify $INCOMING/$(basename "$EXPORT_PKG")" \
    || die "迁移包在目标机校验失败，已中止导入"
ssh_run "dns-stack import $INCOMING/$(basename "$EXPORT_PKG")" \
    || die "目标机导入失败，请登录目标机执行 dns-stack health 查看状态"
log_ok "数据导入完成"

log_step 11 "目标服务器健康检查..."
if ssh_run "dns-stack health"; then
    log_ok "目标服务器健康检查通过"
else
    log_err "目标服务器健康检查未通过，请登录排查后再切流量"
fi

log_step 12 "完成"
echo
echo "旧服务器仍然保持运行，尚未停止或删除。"
echo "恢复过来的配置里含有**原服务器**的地址与路径，切流量前请在目标机确认："
echo "  - /etc/dns-stack/config.env 里的 PUBLIC_IPV4 等需要改成新服务器的地址"
echo "  - TLS 证书需要按新地址重新签发: sudo dns-stack cert-renew"
echo "  - WireGuard 隧道需要在新机与 HK 重新对接:"
echo "      sudo dns-stack wg-peer root@<HK地址>        # 先看清要改什么"
echo "      sudo dns-stack wg-peer root@<HK地址> --apply # 确认后再落盘"
echo
echo "确认新服务器稳定后，在旧服务器执行: sudo dns-stack migration-finish"
exit 0
