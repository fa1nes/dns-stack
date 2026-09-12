#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[[ "${EUID}" -ne 0 ]] && { echo "请使用 root 权限运行: sudo ./deploy.sh $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
用法:
  sudo ./deploy.sh install            安装 dns-stack
  sudo ./deploy.sh update             更新(重新执行安装脚本，幂等)
  sudo ./deploy.sh status             查看运行状态
  sudo ./deploy.sh test               执行健康检查
  sudo ./deploy.sh uninstall          卸载(保留 /etc/dns-stack /var/lib/dns-stack 等持久数据)
  sudo ./deploy.sh uninstall --purge  彻底卸载(删除全部数据，需二次确认)
EOF
}

cmd="${1:-}"
shift || true

case "$cmd" in
    install|update)
        bash "$SCRIPT_DIR/install.sh"
        ;;
    status)
        command -v dns-stack >/dev/null 2>&1 && dns-stack status || echo "dns-stack 尚未安装"
        ;;
    test)
        command -v dns-stack >/dev/null 2>&1 && dns-stack health || echo "dns-stack 尚未安装"
        ;;
    uninstall)
        bash "$SCRIPT_DIR/uninstall.sh" "$@"
        ;;
    *)
        usage
        exit 1
        ;;
esac
