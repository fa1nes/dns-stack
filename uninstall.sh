#!/usr/bin/env bash
set -Eeuo pipefail

C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RESET=$'\033[0m'
log_info() { echo "[信息] $*"; }
log_ok()   { echo "${C_GREEN}[成功]${C_RESET} $*"; }
log_warn() { echo "${C_YELLOW}[警告]${C_RESET} $*"; }
die()      { echo "${C_RED}[错误]${C_RESET} $1" >&2; exit 1; }

[[ "${EUID}" -ne 0 ]] && die "请使用 root 权限运行"

PURGE=0
DRY_RUN=0
for a in "$@"; do
    case "$a" in
        --purge)   PURGE=1 ;;
        --dry-run) DRY_RUN=1 ;;
        *) die "未知参数: $a (用法: uninstall.sh [--purge] [--dry-run])" ;;
    esac
done

run() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "  [dry-run] $*"
    else
        "$@"
    fi
}
[[ "$DRY_RUN" -eq 1 ]] && log_warn "dry-run 模式：只展示将要执行的操作，不会改动任何内容"

log_info "正在停止 dns-stack 相关服务..."
for unit in dns-stack-helper dns-stack-panel dns-stack-classify dns-stack-verify dns-stack-backup \
            dns-stack-sync-rules dns-stack-renew-cert dns-stack-collect-polluted \
            dns-stack-reference-data dns-stack-publish \
            dns-stack-recursive-routing dns-stack-chnroute dns-stack-cn-authority \
            dns-stack-routing-watchdog \
            dns-stack-geoip dns-stack-ecs-zone dns-stack-shared-anycast dns-stack-geo-cross \
            dns-stack-dynamic; do
    run systemctl stop "${unit}.timer" 2>/dev/null || true
    run systemctl disable "${unit}.timer" 2>/dev/null || true
    run systemctl stop "${unit}.service" 2>/dev/null || true
    run systemctl disable "${unit}.service" 2>/dev/null || true
done

if [[ -f /etc/systemd/system/mosproxy.service ]]; then
    log_info "停止 mosproxy(其二进制位于即将删除的 /opt/dns-stack)"
    run systemctl stop mosproxy.service 2>/dev/null || true
    run systemctl disable mosproxy.service 2>/dev/null || true
fi

run rm -f /etc/systemd/system/nftables.service.d/dns-stack.conf
run rmdir /etc/systemd/system/nftables.service.d 2>/dev/null || true
run rm -f /etc/systemd/system/dns-stack-panel.service.d/10-go-panel.conf
run rmdir /etc/systemd/system/dns-stack-panel.service.d 2>/dev/null || true
run rm -f /etc/systemd/system/mosproxy.service.d/10-go-collector.conf
run rmdir /etc/systemd/system/mosproxy.service.d 2>/dev/null || true
run rm -f /etc/systemd/system/dns-stack-helper.service.d/10-go-helper.conf
run rmdir /etc/systemd/system/dns-stack-helper.service.d 2>/dev/null || true
run rm -f /etc/sysctl.d/90-dns-stack.conf
run sysctl --system >/dev/null 2>&1 || true
run rm -f /etc/logrotate.d/dns-stack

run rm -f /usr/local/bin/dns-stack
run rm -rf /opt/dns-stack
run systemctl daemon-reload 2>/dev/null || true

if [[ "$PURGE" -eq 1 ]]; then
    echo
    log_warn "即将永久删除以下全部数据："
    echo "  /etc/dns-stack (含 secrets)"
    echo "  /var/lib/dns-stack"
    echo "  /var/backups/dns-stack"
    echo "  /srv/dns-stack/export"
    echo
    log_warn "⚠️ /etc/dns-stack/secrets/backup-age-identity.txt 是备份解密密钥。"
    log_warn "   删除后，你复制到任何地方的 .tar.zst.age 备份都将**永久无法解密**。"
    if [[ -f /etc/dns-stack/secrets/backup-age-identity.txt ]]; then
        log_warn "   若日后还想恢复数据，请先把这个文件另存到安全的地方再继续。"
    fi
    echo
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "  [dry-run] 此处会要求输入 YES 确认"
    else
        read -r -p "此操作不可撤销，请输入 YES 确认: " confirm
        if [[ "$confirm" != "YES" ]]; then
            log_warn "已取消，未删除任何持久数据"
            exit 0
        fi
    fi
    UNBOUND_WAS_ENABLED=0
    systemctl is-enabled --quiet unbound.service 2>/dev/null && UNBOUND_WAS_ENABLED=1
    run systemctl stop unbound.service 2>/dev/null || true
    run rm -f /etc/unbound/unbound.conf.d/dns-stack.conf
    run rm -f /etc/apparmor.d/local/usr.sbin.unbound
    run rm -f /etc/unbound/dns-stack_*.key /etc/unbound/dns-stack_*.pem
    run rm -rf /etc/dns-stack /var/lib/dns-stack /var/backups/dns-stack /srv/dns-stack/export
    run rm -rf /var/log/dns-stack
    run rm -f /etc/systemd/system/dns-stack-*.service /etc/systemd/system/dns-stack-*.timer
    run rm -f /etc/systemd/system/mosproxy.service
    run systemctl daemon-reload
    run systemctl reset-failed 2>/dev/null || true
    if command -v nft >/dev/null 2>&1; then
        run nft delete table inet dns_route 2>/dev/null || true
    fi
    while ip rule show 2>/dev/null | grep -q 'lookup 100'; do
        run ip rule del lookup 100 2>/dev/null || break
    done
    while ip rule show 2>/dev/null | grep -q '0x1d5 prohibit'; do
        run ip rule del fwmark 0x1d5 prohibit 2>/dev/null || break
    done
    run ip route flush table 100 2>/dev/null || true
    if [[ "$UNBOUND_WAS_ENABLED" -eq 1 ]]; then
        log_info "Unbound 原本是启用状态，已移除本项目配置后重新启动它"
        run systemctl start unbound.service 2>/dev/null || \
            log_warn "  Unbound 启动失败，请检查它自身的配置: journalctl -u unbound"
    fi
    log_ok "已彻底删除全部 dns-stack 数据"
    log_warn "以下内容按设计保留，如不再需要请自行处理："
    echo "  - 系统用户 dns-stack-panel / dns-stack-dynamic (useradd 创建，删除请用 userdel)"
    echo "  - WireGuard 配置 /etc/wireguard/wg0.conf 与云安全组/边界防火墙规则"
    echo "    ⚠️ wg0.conf 里的 Table = off 与 AllowedIPs = 0.0.0.0/0 是本项目改的，"
    echo "       两者必须成对处理：只把 AllowedIPs 改回 /32 是安全的；但若保留"
    echo "       0.0.0.0/0 却删掉 Table = off，wg-quick 下次启动会把整机流量导进隧道"
    echo "  - apt 安装的 unbound / age / zstd 等依赖包"
else
    log_ok "已卸载程序文件，持久数据保留在 /etc/dns-stack /var/lib/dns-stack /var/backups/dns-stack /srv/dns-stack/export"
    log_info "如需彻底删除，请执行: sudo dns-stack uninstall --purge (或 sudo ./uninstall.sh --purge)"
fi
