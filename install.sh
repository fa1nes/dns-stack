#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'; C_RESET=$'\033[0m'
log_info() { echo "${C_CYAN}[信息]${C_RESET} $*"; }
log_ok()   { echo "${C_GREEN}[成功]${C_RESET} $*"; }
log_warn() { echo "${C_YELLOW}[警告]${C_RESET} $*"; }
log_err()  { echo "${C_RED}[错误]${C_RESET} $*" >&2; }
die()      { log_err "$1"; exit 1; }

[[ "${EUID}" -ne 0 ]] && die "请使用 root 权限运行: sudo ./install.sh"

CONFIG_FILE="/etc/dns-stack/config.env"
SECRETS_DIR="/etc/dns-stack/secrets"
OPT_DIR="/opt/dns-stack"
STATE_DIR="/var/lib/dns-stack"
LOG_DIR="/var/log/dns-stack"
BACKUP_DIR="/var/backups/dns-stack"
EXPORT_DIR="/srv/dns-stack/export"

MOSPROXY_COMMON="$SCRIPT_DIR/scripts/mosproxy-artifact-common.sh"
[[ -r "$MOSPROXY_COMMON" ]] || die "缺少 mosproxy 产物校验脚本: $MOSPROXY_COMMON"
source "$MOSPROXY_COMMON"

step1_check_env() {
    log_info "[1/17] 检查当前环境..."
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        log_info "  发行版: ${PRETTY_NAME:-未知}"
        if [[ "${ID:-}" != "debian" && "${ID:-}" != "ubuntu" ]]; then
            die "只支持 Debian/Ubuntu，检测到: ${ID:-未知}"
        fi
    else
        die "无法识别发行版(缺少 /etc/os-release)"
    fi

    ARCH="$(uname -m)"
    log_info "  CPU 架构: ${ARCH}"
    [[ "$ARCH" != "x86_64" && "$ARCH" != "aarch64" ]] && log_warn "架构 ${ARCH} 未经充分测试"

    command -v systemctl >/dev/null 2>&1 || die "系统缺少 systemd，本工具依赖 systemd 管理服务"
    log_ok "  systemd 可用"

    PUB_V4="$(curl -s -4 --max-time 5 https://ifconfig.me 2>/dev/null || echo 未知)"
    PUB_V6="$(curl -s -6 --max-time 5 https://ifconfig.me 2>/dev/null || echo 无)"
    log_info "  公网 IPv4: ${PUB_V4}"
    log_info "  公网 IPv6: ${PUB_V6}"

    log_info "  当前监听端口(53/443/853/5335/8080):"
    ss -tlnup 2>/dev/null | grep -E ':(53|443|853|5335|8080)\b' | sed 's/^/    /' || echo "    (无)"

    for bin in unbound age zstd sqlite3 git; do
        if command -v "$bin" >/dev/null 2>&1; then
            log_info "  已安装: ${bin}"
        else
            log_info "  未安装: ${bin}"
        fi
    done

    AVAIL_KB="$(df -Pk / | tail -1 | awk '{print $4}')"
    log_info "  可用磁盘空间: $((AVAIL_KB/1024))MB"
    [[ "$AVAIL_KB" -lt 2097152 ]] && die "可用磁盘空间不足 2GB，无法继续安装"

    [[ -d /etc/dns-stack ]] && log_warn "  检测到已存在 /etc/dns-stack，本次安装将保留其中数据(幂等)"
    log_ok "环境检查完成"
}

ROLE="global-builder"
step2_role() {
    log_info "[2/17] 确定服务器角色..."
    if [[ -f "$CONFIG_FILE" ]]; then
        EXISTING_ROLE="$(grep -E '^ROLE=' "$CONFIG_FILE" | head -1 | cut -d= -f2- || true)"
        if [[ -n "$EXISTING_ROLE" ]]; then
            ROLE="$EXISTING_ROLE"
            log_info "  沿用已有配置里的角色: ${ROLE}"
        fi
    elif [[ -t 0 ]]; then
        echo "请选择当前服务器角色："
        echo "  1. cn-resolver    (国内 DNS 服务器: mosproxy + Unbound + collector)"
        echo "  2. global-builder (规则构建服务器: 分类器 + 规则发布)"
        read -r -p "请输入选项 [1/2]: " choice
        [[ "$choice" == "1" ]] && ROLE="cn-resolver"
    fi

    case "$ROLE" in
        cn-resolver|global-builder) ;;
        *) die "未知角色: ${ROLE}(只支持 cn-resolver / global-builder)" ;;
    esac
    log_ok "角色: ${ROLE}"
}

cfg_or_default() {
    local key="$1" def="${2:-}"
    if [[ -f "$CONFIG_FILE" ]]; then
        local v
        v="$(grep -E "^${key}=" "$CONFIG_FILE" | head -1 | cut -d= -f2- || true)"
        [[ -n "$v" ]] && { echo "$v"; return; }
    fi
    echo "$def"
}

ensure_config_env() {
    mkdir -p "$(dirname "$CONFIG_FILE")"
    if [[ ! -f "$CONFIG_FILE" ]]; then
        cp -a "$SCRIPT_DIR/config.example.env" "$CONFIG_FILE"
        log_ok "  已生成 ${CONFIG_FILE}"
    else
        local added=0 line key
        while IFS= read -r line; do
            [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
            key="${line%%=*}"
            grep -qE "^${key}=" "$CONFIG_FILE" && continue
            echo "$line" >> "$CONFIG_FILE"
            added=$((added + 1))
        done < "$SCRIPT_DIR/config.example.env"
        if [[ "$added" -gt 0 ]]; then
            log_ok "  已补齐 ${added} 个缺失的配置项(原有值未改动)"
        else
            log_info "  ${CONFIG_FILE} 配置项完整"
        fi
    fi
    if grep -qE '^ROLE=' "$CONFIG_FILE"; then
        sed -i "s|^ROLE=.*|ROLE=${ROLE}|" "$CONFIG_FILE"
    else
        printf 'ROLE=%s\n' "$ROLE" >> "$CONFIG_FILE"
    fi
    if id -u dns-stack-panel >/dev/null 2>&1; then
        chgrp dns-stack-panel "$CONFIG_FILE" && chmod 0640 "$CONFIG_FILE"
    else
        chmod 0644 "$CONFIG_FILE"
    fi
}

ensure_tls_cert() {
    if [[ -f "$SECRETS_DIR/doh-dot.pem" && -f "$SECRETS_DIR/doh-dot.key" ]]; then
        log_info "  证书已存在，跳过"
        return 0
    fi
    log_warn "  未找到证书，先生成自签证书兜底(对外服务前请执行 dns-stack cert-renew 换正式证书)"
    mkdir -p "$SECRETS_DIR"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout "$SECRETS_DIR/doh-dot.key" -out "$SECRETS_DIR/doh-dot.pem" \
        -subj "/CN=dns-stack" 2>/dev/null \
        || die "自签证书生成失败，请确认已安装 openssl"
    chmod 0600 "$SECRETS_DIR/doh-dot.key"
    chmod 0644 "$SECRETS_DIR/doh-dot.pem"
}

step3_backup_existing() {
    log_info "[3/17] 备份已有相关配置..."
    local ts backup_target
    ts="$(date '+%Y%m%d%H%M%S')"
    backup_target="${BACKUP_DIR}/pre-install-${ts}"
    mkdir -p "$backup_target"
    [[ -d /etc/unbound ]] && cp -a /etc/unbound "$backup_target/unbound-etc" 2>/dev/null || true
    [[ -f "$CONFIG_FILE" ]] && cp -a "$CONFIG_FILE" "$backup_target/" 2>/dev/null || true
    log_ok "备份完成: ${backup_target}"
}

step5_create_dirs() {
    log_info "[5/17] 创建目录隔离结构..."
    mkdir -p "$OPT_DIR" "$STATE_DIR" "$LOG_DIR" "$BACKUP_DIR" "$EXPORT_DIR" /etc/dns-stack /run/dns-stack
    mkdir -p "$SECRETS_DIR"
    chmod 0755 "$OPT_DIR" /etc/dns-stack "$EXPORT_DIR"
    chmod 0750 "$STATE_DIR" "$LOG_DIR" "$BACKUP_DIR"

    mkdir -p "$STATE_DIR/geoip"
    chgrp dns-stack-panel "$STATE_DIR/geoip" 2>/dev/null || true
    chmod 2755 "$STATE_DIR/geoip"
    chmod 0710 "$SECRETS_DIR"
    if id -u dns-stack-panel >/dev/null 2>&1; then
        chgrp dns-stack-panel "$SECRETS_DIR"
    fi
    log_ok "目录就绪"
}

step6_install_deps() {
    log_info "[6/17] 安装固定版本依赖..."
    if [[ ! -f "$OPT_DIR/versions.lock" ]] || [[ ! -f "$SCRIPT_DIR/versions.lock" ]]; then
        cp -a "$SCRIPT_DIR/versions.lock" "$OPT_DIR/versions.lock" 2>/dev/null || true
    fi

    local need_install=()
    command -v unbound   >/dev/null 2>&1 || need_install+=("unbound")
    command -v age       >/dev/null 2>&1 || need_install+=("age")
    command -v socat >/dev/null 2>&1 || need_install+=("socat")
    command -v dig   >/dev/null 2>&1 || need_install+=("dnsutils")
    command -v zstd  >/dev/null 2>&1 || need_install+=("zstd")
    command -v sqlite3 >/dev/null 2>&1 || need_install+=("sqlite3")
    command -v curl  >/dev/null 2>&1 || need_install+=("curl")
    command -v openssl >/dev/null 2>&1 || need_install+=("openssl")
    command -v git >/dev/null 2>&1 || need_install+=("git")
    command -v nft >/dev/null 2>&1 || need_install+=("nftables")

    if [[ "${#need_install[@]}" -gt 0 ]]; then
        log_info "  需要安装: ${need_install[*]}"
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${need_install[@]}" \
            || die "依赖安装失败，请检查 apt 源后重试: ${need_install[*]}"
    else
        log_info "  依赖已全部安装，跳过"
    fi

    record_installed_versions
    log_ok "依赖就绪"
}

record_installed_versions() {
    local lock="$OPT_DIR/versions.lock" tmp
    tmp="$(mktemp)"
    {
        echo "{"
        echo "  \"recorded_at\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
        echo "  \"os\": \"$(. /etc/os-release && echo "${PRETTY_NAME:-unknown}")\","
        echo "  \"kernel\": \"$(uname -r)\","
        echo "  \"packages\": {"
        local first=1 p v
        for p in unbound age socat dnsutils zstd sqlite3 curl openssl git nftables; do
            v="$(dpkg-query -W -f='${Version}' "$p" 2>/dev/null || echo "")"
            [[ -z "$v" ]] && continue
            [[ "$first" -eq 1 ]] && first=0 || echo ","
            printf '    "%s": "%s"' "$p" "$v"
        done
        echo
        echo "  },"
        echo "  \"mosproxy\": \"$(mosproxy_expected_repo "$SCRIPT_DIR" 2>/dev/null || echo unknown)@$(mosproxy_installed_version "$OPT_DIR/bin/mosproxy" 2>/dev/null || echo unknown)\","
        echo "  \"dns_stack\": \"$("$OPT_DIR/bin/dns-stack-go" version 2>/dev/null | awk '{print $2}' || echo unknown)\""
        echo "}"
    } > "$tmp"
    mv -f "$tmp" "$lock"
    chmod 0644 "$lock"
}

step7_deploy_unbound() {
    log_info "[7/17] 部署 Unbound..."
    mkdir -p /etc/unbound/unbound.conf.d /etc/apparmor.d/local

    local wg_block=""
    if [[ "$ROLE" == "cn-resolver" ]]; then
        local wg_self wg_peer
        wg_self="$(cfg_or_default CN_SERVER_WG_IP 10.100.0.2)"
        wg_peer="$(cfg_or_default GLOBAL_SERVER_WG_IP 10.100.0.3)"
        wg_block=$'\n    # 国内专用递归接口：仅对 WireGuard 隧道内的规则构建节点开放\n'
        wg_block+="    interface: ${wg_self}@5335"$'\n'
        wg_block+="    access-control: ${wg_peer}/32 allow"
    fi
    awk -v blk="$wg_block" '{ gsub(/\{\{CN_WG_INTERFACE\}\}/, blk); print }' \
        "$SCRIPT_DIR/unbound/unbound.template.conf" > /etc/unbound/unbound.conf.d/dns-stack.conf

    if [[ -f /etc/apparmor.d/usr.sbin.unbound ]]; then
        cp -a "$SCRIPT_DIR/systemd/apparmor-local-usr.sbin.unbound" /etc/apparmor.d/local/usr.sbin.unbound
        apparmor_parser -r /etc/apparmor.d/usr.sbin.unbound 2>/dev/null || true
    fi

    if [[ ! -f /etc/unbound/dns-stack_server.pem ]]; then
        log_info "  生成 unbound-control 证书..."
        pushd /etc/unbound >/dev/null
        openssl genrsa -out dns-stack_server.key 3072 2>/dev/null
        openssl req -new -key dns-stack_server.key -out dns-stack_server.csr -subj "/CN=unbound" 2>/dev/null
        openssl x509 -req -in dns-stack_server.csr -days 7200 -signkey dns-stack_server.key -out dns-stack_server.pem 2>/dev/null
        openssl genrsa -out dns-stack_control.key 3072 2>/dev/null
        openssl req -new -key dns-stack_control.key -out dns-stack_control.csr -subj "/CN=unbound-control" 2>/dev/null
        openssl x509 -req -in dns-stack_control.csr -days 7200 -CA dns-stack_server.pem -CAkey dns-stack_server.key -CAcreateserial -out dns-stack_control.pem 2>/dev/null
        rm -f dns-stack_server.csr dns-stack_control.csr dns-stack_server.srl
        chown unbound:unbound dns-stack_server.key dns-stack_server.pem dns-stack_control.key dns-stack_control.pem
        chmod 0600 dns-stack_server.key dns-stack_control.key
        chmod 0640 dns-stack_server.pem dns-stack_control.pem
        popd >/dev/null
    fi

    chgrp unbound "$LOG_DIR" 2>/dev/null || true
    chmod 0750 "$LOG_DIR"
    touch "$LOG_DIR/unbound.log"
    chown unbound:unbound "$LOG_DIR/unbound.log" 2>/dev/null || true
    for f in "$LOG_DIR/helper.log" "$LOG_DIR/dns-stack.log"; do
        touch "$f"
        chmod 0640 "$f"
    done

    systemctl disable --now unbound-resolvconf.service 2>/dev/null || true

    unbound-checkconf || die "unbound 配置校验失败"

    systemctl stop unbound.service 2>/dev/null || true
    sleep 1
    systemctl reset-failed unbound.service 2>/dev/null || true
    systemctl enable --now unbound.service || die "unbound 启动失败，请查看: journalctl -xeu unbound.service 和 ${LOG_DIR}/unbound.log"

    local ok=0 i
    for i in $(seq 1 10); do
        if dig @127.0.0.1 -p 5335 example.com A +time=5 +tries=1 +short >/dev/null 2>&1; then
            ok=1
            break
        fi
        sleep 2
    done
    [[ "$ok" -eq 1 ]] || die "unbound 递归解析测试失败(已重试 10 次)，请查看: journalctl -xeu unbound.service"
    log_ok "Unbound 运行正常"
}

GO_RUNTIME_DONE=0
install_go_runtime() {
    [[ "$GO_RUNTIME_DONE" -eq 1 ]] && return 0
    local arch candidate="" target="$OPT_DIR/bin/dns-stack-go"
    case "$(uname -m)" in
        x86_64|amd64) arch=amd64 ;;
        aarch64|arm64) arch=arm64 ;;
        *) die "不支持的架构 $(uname -m)：整套运行时是单个 Go 二进制，没有其它实现可退" ;;
    esac

    local download_dir=""
    if [[ -f "$SCRIPT_DIR/bin/dns-stack-linux-${arch}" ]]; then
        candidate="$SCRIPT_DIR/bin/dns-stack-linux-${arch}"
    else
        local repo base
        repo="${DNS_STACK_BINARY_REPO:-$(cfg_or_default GITHUB_REPOSITORY "")}"
        base="${DNS_STACK_BINARY_BASE:-${repo:+https://github.com/${repo}/releases/download/binaries-latest}}"
        [[ -n "$base" ]] || die "bin/ 里没有预编产物，且未配置 GITHUB_REPOSITORY，无从下载 Go 二进制

  这台机器上不编译是有意的：生产机的规格与依赖都不受控，2026-09-07 的 OOM 事故
  就是从"在生产机上跑没做过规模测试的代码"开始的。构建一律在 CI 完成。
  解决办法二选一：
    1) 在 /etc/dns-stack/config.env 里配好 GITHUB_REPOSITORY，让本脚本自动下载
    2) 从 GitHub Releases 手工下载 dns-stack-linux-${arch}，放到 ${SCRIPT_DIR}/bin/"
        download_dir="$(mktemp -d)"
        log_info "  从 CI 产物下载一体化 Go 二进制($arch)..."
        if ! curl -fsSL --retry 3 --max-time 300 \
                -o "$download_dir/dns-stack" "${base}/dns-stack-linux-${arch}"; then
            rm -rf "$download_dir"
            die "下载 ${base}/dns-stack-linux-${arch} 失败；确认该 Release 存在且网络可达"
        fi
        if curl -fsSL --retry 2 --max-time 60 \
                -o "$download_dir/dns-stack.sha256" "${base}/dns-stack-linux-${arch}.sha256"; then
            local want got
            want="$(awk '{print $1}' "$download_dir/dns-stack.sha256")"
            got="$(sha256sum "$download_dir/dns-stack" | awk '{print $1}')"
            if [[ "$want" != "$got" ]]; then
                rm -rf "$download_dir"
                die "下载的二进制 sha256 与 CI 记录不符（期望 $want，实际 $got）"
            fi
            log_ok "  sha256 与 CI 记录一致"
        else
            log_warn "  取不到 .sha256，跳过校验（内容未经核对）"
        fi
        chmod 0755 "$download_dir/dns-stack"
        candidate="$download_dir/dns-stack"
    fi

    install -d -m 0755 "$OPT_DIR/bin"
    install -m 0755 -o root -g root "$candidate" "$target.install.$$"
    [[ -n "$download_dir" ]] && rm -rf "$download_dir"
    if ! "$target.install.$$" version >/dev/null 2>&1; then
        rm -f "$target.install.$$"
        die "Go 二进制无法在本机执行——确认下载的架构与 $(uname -m) 一致"
    fi
    mv -f "$target.install.$$" "$target"
    printf '%s  %s\n' "$(sha256sum "$target" | awk '{print $1}')" dns-stack-go \
        > "$target.sha256"
    chmod 0644 "$target.sha256"
    log_ok "  面板后端已切到一体化 Go 二进制($($target version))"

    log_ok "  管理助手已切到一体化 Go 二进制"

    if [[ "$ROLE" == "cn-resolver" ]]; then
        log_ok "  查询采集器已切到一体化 Go 二进制"
    fi
    systemctl daemon-reload
    GO_RUNTIME_DONE=1
}

install_mosproxy_candidate() {
    local candidate="$1" expected="$2" origin="$3"
    local target="$OPT_DIR/bin/mosproxy"
    local staged="$OPT_DIR/bin/.mosproxy.install.$$"
    local backup

    install -m 0755 "$candidate" "$staged"
    if ! mosproxy_binary_matches "$staged" "$expected"; then
        rm -f "$staged"
        log_warn "  ${origin} 的二进制不含当前补丁指纹 ${expected}，拒绝安装"
        return 1
    fi

    if [[ -e "$target" ]] && ! mosproxy_binary_matches "$target" "$expected"; then
        backup="$BACKUP_DIR/mosproxy-pre-${expected//\//_}-$(date '+%Y%m%d%H%M%S')"
        cp -a "$target" "$backup"
        log_warn "  旧 mosproxy 已备份: $backup"
    fi

    mv -f "$staged" "$target"
    mosproxy_write_metadata "$target" "$expected"
    log_info "  mosproxy 来源: ${origin}"
}

download_mosproxy() {
    local repo="$1" arch="$2"
    local direct="https://github.com/${repo}/releases/latest/download/mosproxy-linux-${arch}"
    local srcs=(
        "https://ghfast.top/${direct}"
        "https://gh-proxy.com/${direct}"
        "https://ghproxy.net/${direct}"
        "${direct}"
    )
    local tmp="$OPT_DIR/bin/.mosproxy.dl" sum="${tmp}.sha256" build_id="${tmp}.build-id"
    local u released installed
    for u in "${srcs[@]}"; do
        rm -f "$tmp" "$sum" "$build_id"
        curl -fsSL --max-time 300 "$u" -o "$tmp" 2>/dev/null || continue
        [[ -s "$tmp" ]] || continue
        if ! curl -fsSL --max-time 60 "${u}.sha256" -o "$sum" 2>/dev/null; then
            log_warn "  取不到校验和，换下一个源"
            continue
        fi
        if ! curl -fsSL --max-time 60 "${u}.build-id" -o "$build_id" 2>/dev/null; then
            log_warn "  取不到构建身份，换下一个源"
            continue
        fi
        chmod +x "$tmp"
        if ! released="$(mosproxy_artifact_version "$tmp")"; then
            log_warn "  build-id 不是 vX.Y.Z 形式，换下一个源"
            continue
        fi
        if ! mosproxy_artifact_matches "$tmp" "$released"; then
            log_warn "  最新版 ${released} 的产物自检不通过($(du -h "$tmp" | cut -f1))，换下一个源"
            continue
        fi
        installed="$(mosproxy_installed_version "$OPT_DIR/bin/mosproxy" 2>/dev/null || true)"
        if [[ "$installed" == "$released" ]] \
           && mosproxy_checksum_matches "$OPT_DIR/bin/mosproxy" "$sum"; then
            mosproxy_write_metadata "$OPT_DIR/bin/mosproxy" "$released"
            log_info "  已安装的 mosproxy 就是最新版 ${released}，保留不动"
            rm -f "$tmp" "$sum" "$build_id"
            return 0
        fi
        if install_mosproxy_candidate "$tmp" "$released" "${repo} 最新 Release ${released}"; then
            rm -f "$tmp" "$sum" "$build_id"
            return 0
        fi
    done
    rm -f "$tmp" "$sum" "$build_id"
    return 1
}

step8_deploy_mosproxy() {
    log_info "[8/17] 部署 mosproxy..."
    mkdir -p "$OPT_DIR/bin" /etc/dns-stack/mosproxy

    local mp_repo mp_arch expected bundled bundled_version candidate locked_repo
    locked_repo="$(mosproxy_expected_repo "$SCRIPT_DIR")" \
        || die "versions.lock 里的 mosproxy repo 不是 owner/name 形式"
    mp_repo="$(cfg_or_default MOSPROXY_REPO "$locked_repo")"
    case "$(uname -m)" in
        x86_64|amd64) mp_arch=amd64 ;;
        aarch64|arm64) mp_arch=arm64 ;;
        *) mp_arch="" ;;
    esac
    [[ -n "$mp_arch" ]] || die "不支持为 $(uname -m) 部署 mosproxy"

    bundled=""
    for candidate in "$SCRIPT_DIR/bin/mosproxy-linux-${mp_arch}" "$SCRIPT_DIR/bin/mosproxy"; do
        [[ -f "$candidate" ]] || continue
        chmod +x "$candidate"
        if bundled_version="$(mosproxy_artifact_version "$candidate")" \
           && mosproxy_artifact_matches "$candidate" "$bundled_version"; then
            bundled="$candidate"
            break
        fi
    done

    if [[ -n "$bundled" ]] \
       && install_mosproxy_candidate "$bundled" "$bundled_version" "源码包已验证产物 ${bundled_version}"; then
        :
    elif download_mosproxy "$mp_repo" "$mp_arch"; then
        :
    else
        die "取不到 ${mp_repo} 最新 Release 的 mosproxy-linux-${mp_arch}。不在生产机编译，请确认该仓库已发布 Release 且随产物附带 .sha256 与 .build-id"
    fi

    expected="$(mosproxy_artifact_version "$OPT_DIR/bin/mosproxy")" \
        || die "mosproxy 安装后缺少 build-id 或其格式不是 vX.Y.Z"
    mosproxy_artifact_matches "$OPT_DIR/bin/mosproxy" "$expected" \
        || die "mosproxy 安装后的版本指纹或 SHA256 复核失败"
    log_ok "  mosproxy ${expected} 就位"

    local tpl_rev cur_rev
    tpl_rev="$(grep -m1 -oE '^# template-rev:[[:space:]]*[0-9]+' \
               "$SCRIPT_DIR/mosproxy/config.template.yaml" | grep -oE '[0-9]+$' || echo 0)"
    cur_rev="$(grep -m1 -oE '^# template-rev:[[:space:]]*[0-9]+' \
               /etc/dns-stack/mosproxy/config.yaml 2>/dev/null | grep -oE '[0-9]+$' || echo 0)"
    if [[ -f /etc/dns-stack/mosproxy/config.yaml && "$cur_rev" == "$tpl_rev" && "$tpl_rev" != "0" ]]; then
        log_info "  mosproxy 配置已是 rev ${tpl_rev}，保留不动"
    else
        local doh_port dot_port doh_path ub_port cert key cc qps old_cfg
        doh_port="$(cfg_or_default DOH_PORT 443)"
        dot_port="$(cfg_or_default DOT_PORT 853)"
        doh_path="$(cfg_or_default DOH_PATH "")"
        if [[ -z "$doh_path" ]]; then
            doh_path="/$(openssl rand -hex 16)/dns-query"
            if grep -qE '^DOH_PATH=' /etc/dns-stack/config.env 2>/dev/null; then
                sed -i -E "s|^DOH_PATH=.*|DOH_PATH=${doh_path}|" /etc/dns-stack/config.env
            else
                echo "DOH_PATH=${doh_path}" >> /etc/dns-stack/config.env
            fi
            log_ok "  已生成 DoH 私密路径(接入地址见安装结束时的提示)"
        fi
        ub_port="$(cfg_or_default UNBOUND_PORT 5335)"
        cert="$SECRETS_DIR/doh-dot.pem"
        key="$SECRETS_DIR/doh-dot.key"
        cc=$(( $(nproc) * 250 )); qps=$(( $(nproc) * 1000 ))
        old_cfg=""
        if [[ -f /etc/dns-stack/mosproxy/config.yaml ]]; then
            old_cfg="/etc/dns-stack/mosproxy/config.yaml.pre-routing-upgrade-$(date '+%Y%m%d%H%M%S')"
            cp -a /etc/dns-stack/mosproxy/config.yaml "$old_cfg"
            log_warn "  检测到旧路由配置，已备份: $old_cfg"
        fi
        sed -e "s|{{DOH_PORT}}|${doh_port}|g" \
            -e "s|{{DOT_PORT}}|${dot_port}|g" \
            -e "s|{{DOH_PATH}}|${doh_path}|g" \
            -e "s|{{UNBOUND_PORT}}|${ub_port}|g" \
            -e "s|{{TLS_CERT_PATH}}|${cert}|g" \
            -e "s|{{TLS_KEY_PATH}}|${key}|g" \
            -e "s|{{LIMIT_CONCURRENT}}|${cc}|g" \
            -e "s|{{LIMIT_QPS}}|${qps}|g" \
            "$SCRIPT_DIR/mosproxy/config.template.yaml" > /etc/dns-stack/mosproxy/config.yaml
        log_ok "  已生成 /etc/dns-stack/mosproxy/config.yaml (rev ${tpl_rev})"
    fi

    for f in cn.txt gfw.txt manual-cn.txt manual-gfw.txt manual-exclude.txt \
             cn-ip-cidr.txt polluted-ip-cidr.txt polluted-ip.txt; do
        [[ -f "$STATE_DIR/$f" ]] || : > "$STATE_DIR/$f"
    done
    chmod 0644 "$STATE_DIR"/*.txt 2>/dev/null || true

    cp -a "$SCRIPT_DIR/systemd/mosproxy.service" /etc/systemd/system/mosproxy.service
    systemctl daemon-reload
    systemctl enable mosproxy.service
    log_ok "mosproxy 已部署(将在 collector 装好后启动)"
}

step9_placeholder_db() {
    if [[ "$ROLE" == "cn-resolver" ]]; then
        log_info "[9/17] collector.db 将在采集器首次运行时自动建表(见 internal/collect/db.go)"
    else
        log_info "[9/17] classifier.db 将在分类器首次运行时自动建表(见 internal/classify/store.go)"
    fi
}

step10_deploy_collector() {
    log_info "[10/17] 部署查询采集器..."
    install_go_runtime

    systemctl restart mosproxy.service || die "mosproxy 启动失败，请查看: journalctl -xeu mosproxy"
    sleep 2
    systemctl is-active --quiet mosproxy.service || die "mosproxy 未处于运行状态"
    log_ok "collector / 动态分流器已安装，mosproxy 已启动"
}

step10_deploy_classifier() {
    log_info "[10/17] 部署规则构建分类器..."
    install_go_runtime
    "$OPT_DIR/bin/dns-stack-go" classify status >/dev/null 2>&1 \
        || log_info "  分类库尚未初始化，首次运行 classify pipeline 时会自动建表"
    log_ok "分类器随一体化 Go 二进制安装完成"
}

step11_deploy_helper() {
    log_info "[11/17] 部署受限 root 管理助手..."
    install_go_runtime
    cp -a "$SCRIPT_DIR/systemd/dns-stack-helper.service" /etc/systemd/system/dns-stack-helper.service
    systemctl daemon-reload
    systemctl enable dns-stack-helper.service
    systemctl restart dns-stack-helper.service || die "helper 服务启动失败"
    log_ok "helper 已启动"
}

step12_deploy_panel() {
    log_info "[12/17] 部署中文管理面板..."

    if ! id -u dns-stack-panel >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin dns-stack-panel
        log_info "  已创建系统用户 dns-stack-panel(非 root)"
    fi
    chgrp dns-stack-panel "$STATE_DIR"
    chmod 2771 "$STATE_DIR"
    find "$STATE_DIR" -mindepth 1 -maxdepth 1 \
        -exec chgrp -R dns-stack-panel {} + 2>/dev/null || true
    find "$STATE_DIR" -mindepth 1 -maxdepth 1 \
        -exec chmod -R g+rwX {} + 2>/dev/null || true

    chgrp dns-stack-panel "$CONFIG_FILE" 2>/dev/null && chmod 0640 "$CONFIG_FILE" || true

    chmod 0710 "$SECRETS_DIR"
    chgrp dns-stack-panel "$SECRETS_DIR"
    install -d -o dns-stack-panel -g dns-stack-panel -m 0750 "$SECRETS_DIR/panel"

    cp -a "$SCRIPT_DIR/systemd/dns-stack-panel.service" /etc/systemd/system/dns-stack-panel.service
    install_go_runtime
    systemctl daemon-reload
    systemctl enable dns-stack-panel.service

    systemctl restart dns-stack-helper.service
    systemctl restart dns-stack-panel.service || die "面板启动失败"

    sleep 2
    local listen host port scheme url
    listen="$(cfg_or_default PANEL_LISTEN 127.0.0.1:8080)"
    listen="${listen// /}"
    if [[ "$listen" =~ ^\[(.+)\]:([0-9]+)$ ]]; then            # [::1]:8080
        host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
    elif [[ "$listen" =~ ^([^:]+):([0-9]+)$ ]]; then           # 127.0.0.1:8080
        host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
    else
        host="$listen"; port="$(cfg_or_default PANEL_PORT 8080)"
    fi
    case "$host" in 0.0.0.0|"::"|"") host="127.0.0.1" ;; esac
    if [[ "$host" == "127.0.0.1" || "$host" == "::1" || "$host" == "localhost" ]] \
       && [[ "$(cfg_or_default PANEL_PUBLIC false)" != "true" ]]; then
        scheme="http"
    else
        scheme="https"
    fi
    url="${scheme}://${host}:${port}/api/health"

    local i probe_ok=0
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -skf --max-time 3 "$url" >/dev/null 2>&1; then probe_ok=1; break; fi
        sleep 1
    done
    [[ "$probe_ok" -eq 1 ]] \
        || log_warn "面板健康检查未通过(${url})，请查看: journalctl -xeu dns-stack-panel"

    if [[ "$scheme" == "https" ]]; then
        log_ok "面板已启动: ${scheme}://<本机IP>:${port} (公网访问，需密码登录)"
        [[ -r /etc/dns-stack/secrets/panel/auth.json ]] \
            || log_warn "  尚未设置访问密码，面板会拒绝非本机访问: sudo dns-stack panel-password"
    else
        log_ok "面板已启动: ${scheme}://127.0.0.1:${port} (仅本机监听，需 SSH 隧道或 WireGuard 访问)"
    fi
}

step13_deploy_shell() {
    log_info "[13/17] 部署中文 Shell 管理工具与完整源码树..."
    local source_root target_root
    mkdir -p "$OPT_DIR/dns-stack"
    source_root="$(readlink -f "$SCRIPT_DIR")"
    target_root="$(readlink -f "$OPT_DIR/dns-stack")"

    if [[ "$source_root" != "$target_root" ]]; then
        for item in install.sh uninstall.sh config.example.env versions.lock bin \
                    panel helper collector classifier lib systemd unbound mosproxy rules docs patches \
                    scripts migration; do
            [[ -e "$SCRIPT_DIR/$item" ]] || continue
            rm -rf "$OPT_DIR/dns-stack/${item:?}"
            cp -a "$SCRIPT_DIR/$item" "$OPT_DIR/dns-stack/"
        done
    else
        log_info "  源码已位于目标目录，跳过自复制"
    fi

    cp -a "$SCRIPT_DIR/bin/dns-stack" /usr/local/bin/dns-stack

    chmod +x "$OPT_DIR/dns-stack/scripts/"*.sh "$OPT_DIR/dns-stack/migration/"*.sh \
             /usr/local/bin/dns-stack
    chmod +x "$OPT_DIR/dns-stack/install.sh" 2>/dev/null || true
    log_ok "dns-stack 命令已就绪: /usr/local/bin/dns-stack"
    log_ok "完整源码树已就位: ${OPT_DIR}/dns-stack (dns-stack migrate 依赖它)"
}

step14_confirm_publish() {
    log_info "[14/17] 规则发布程序: ${OPT_DIR}/bin/dns-stack-go classify publish (随一体化二进制安装，已就绪)"
}

step15_cert() {
    if [[ "$ROLE" != "cn-resolver" ]]; then
        log_info "[15/17] 规则构建节点不对外提供 DoH/DoT，跳过 TLS 证书管理"
        return 0
    fi
    log_info "[15/17] 配置 TLS 证书(DoH 公网入口需要)..."
    ensure_tls_cert

    cp -a "$SCRIPT_DIR/systemd/dns-stack-renew-cert.service" /etc/systemd/system/ 2>/dev/null || true
    cp -a "$SCRIPT_DIR/systemd/dns-stack-renew-cert.timer" /etc/systemd/system/ 2>/dev/null || true
    systemctl daemon-reload
    systemctl enable --now dns-stack-renew-cert.timer 2>/dev/null || true
    log_ok "证书就绪，续签 timer 已启用"
}

install_timers() {
    local unit
    for unit in "$@"; do
        [[ -f "$SCRIPT_DIR/systemd/${unit}.service" ]] || {
            log_warn "  缺少单元文件 ${unit}.service，跳过"; continue; }
        cp -a "$SCRIPT_DIR/systemd/${unit}.service" /etc/systemd/system/
        cp -a "$SCRIPT_DIR/systemd/${unit}.timer" /etc/systemd/system/ 2>/dev/null || true
    done
    systemctl daemon-reload
    for unit in "$@"; do
        [[ -f "/etc/systemd/system/${unit}.timer" ]] || continue
        systemctl enable --now "${unit}.timer" 2>/dev/null \
            || log_warn "  ${unit}.timer 启用失败"
    done
}

step_backup_timer() {
    log_info "启用自动备份..."
    install_timers dns-stack-backup
    log_ok "自动备份已启用(每日 04:00，保留策略见 config.env)"
}

step_cn_timers() {
    log_info "启用国内角色的定时任务..."
    install_timers dns-stack-sync-rules dns-stack-collect-polluted \
                   dns-stack-chnroute dns-stack-cn-authority dns-stack-ecs-zone dns-stack-geoip \
                   dns-stack-shared-anycast dns-stack-geo-cross
    log_ok "定时任务已启用(规则同步 5 分钟 / 污染采集 6 小时 / 大陆 IP 表每日 / 墙内权威 15 分钟 / ECS 分片每日 / 归属库每周 / 共享 anycast 每小时 / 多源交叉每日)"
    if [[ ! -f "$STATE_DIR/chnroute/shared-anycast.txt" ]]; then
        log_info "首次生成共享 anycast 权威清单(失败不影响安装)..."
        systemctl start dns-stack-shared-anycast.service 2>/dev/null \
            && log_ok "共享 anycast 清单已就绪" \
            || log_warn "共享 anycast 清单未生成，稍后由 timer 重试"
    fi
    if [[ ! -f "$STATE_DIR/geoip/GeoLite2-ASN.mmdb" ]]; then
        log_info "首次拉取 IP 归属库(失败不影响安装)..."
        systemctl start dns-stack-geoip.service 2>/dev/null \
            && log_ok "归属库已就绪" \
            || log_warn "归属库拉取未成功，稍后由 dns-stack-geoip.timer 重试"
    fi
    if [[ ! -f "$STATE_DIR/chnroute/geo-disputed.txt" ]]; then
        log_info "首次生成多归属库交叉清单(失败不影响安装)..."
        systemctl start dns-stack-geo-cross.service 2>/dev/null \
            && log_ok "多源交叉清单已就绪" \
            || log_warn "多源交叉清单未生成，稍后由 dns-stack-geo-cross.timer 重试"
    fi
}

step_logrotate() {
    log_info "配置日志轮转..."
    local src="$SCRIPT_DIR/docs/logrotate-dns-stack.conf"
    local dst="/etc/logrotate.d/dns-stack"
    [[ -f "$src" ]] || { log_warn "  缺少 $src，跳过"; return 0; }

    install -m 0644 "$src" "$dst"

    if logrotate --debug "$dst" >/dev/null 2>&1; then
        log_ok "日志轮转已配置($dst，每周、保留 4 份、压缩)"
    else
        log_warn "  logrotate 配置校验未通过，日志仍会无限增长"
        log_warn "  排查: logrotate --debug $dst"
    fi
}

step_sysctl() {
    log_info "配置内核参数..."
    local src="$SCRIPT_DIR/docs/sysctl-cn.conf"
    local dst="/etc/sysctl.d/90-dns-stack.conf"
    [[ -f "$src" ]] || { log_warn "  缺少 $src，跳过"; return 0; }

    local panel_port
    panel_port="$(cfg_or_default PANEL_LISTEN 127.0.0.1:8080)"
    panel_port="${panel_port##*:}"
    [[ "$panel_port" =~ ^[0-9]+$ ]] || panel_port="$(cfg_or_default PANEL_PORT 8080)"

    sed -E "s|^(net\.ipv4\.ip_local_reserved_ports =).*|\1 5335,8888,8953,${panel_port}|" \
        "$src" > "$dst"
    chmod 0644 "$dst"

    if sysctl --system >/dev/null 2>&1; then
        log_ok "内核参数已应用($dst)"
        local v
        v="$(sysctl -n net.netfilter.nf_conntrack_udp_timeout 2>/dev/null || echo "")"
        if [[ "$v" == "10" ]]; then
            log_ok "  conntrack UDP 超时已收紧至 10 秒"
        else
            log_warn "  conntrack 参数未生效(当前值: ${v:-未加载})，"
            log_warn "  多半是 nf_conntrack 模块尚未加载；分流链装好后会自动加载，届时重跑本步"
        fi
    else
        log_warn "  sysctl --system 执行失败，参数未生效"
    fi
}

step_recursive_routing() {
    log_info "配置递归出口分流..."

    if ! command -v nft >/dev/null 2>&1; then
        log_warn "  未找到 nft(nftables)，跳过递归分流配置"
        return 0
    fi
    if ! ip link show wg0 >/dev/null 2>&1; then
        log_warn "  未找到 wg0 隧道，跳过递归分流配置"
        log_warn "  隧道就绪后执行: systemctl start dns-stack-chnroute dns-stack-recursive-routing"
        return 0
    fi

    cp -a "$SCRIPT_DIR/systemd/dns-stack-recursive-routing.service" /etc/systemd/system/

    cp -a "$SCRIPT_DIR/systemd/dns-stack-routing-watchdog.service" /etc/systemd/system/
    cp -a "$SCRIPT_DIR/systemd/dns-stack-routing-watchdog.timer" /etc/systemd/system/

    systemctl daemon-reload
    systemctl enable dns-stack-recursive-routing.service 2>/dev/null || true
    systemctl enable --now dns-stack-routing-watchdog.timer 2>/dev/null || true

    if "$SCRIPT_DIR/scripts/update-chnroute.sh"; then
        if systemctl start dns-stack-recursive-routing.service; then
            log_ok "递归出口分流已启用(大陆直连 / 境外经隧道)"
            "$SCRIPT_DIR/scripts/update-cn-authority.sh" >/dev/null 2>&1 \
                && log_ok "墙内域名权威集合已初始化" \
                || log_info "  墙内权威集合待 Unbound 积累数据后由 timer 自动生成"
        else
            log_warn "  分流链安装失败: journalctl -u dns-stack-recursive-routing"
        fi
    else
        log_warn "  大陆 IP 集合构建失败，暂不安装分流链(维持全部直连)"
        log_warn "  网络恢复后执行: systemctl start dns-stack-chnroute dns-stack-recursive-routing"
    fi
}

step_global_timers() {
    log_info "启用规则构建角色的规则流水线定时任务..."
    install_timers dns-stack-reference-data dns-stack-classify dns-stack-verify
    log_ok "参考数据(每日) / 候选增量分类(5 分钟) / 权威位置分类(6 小时) / 正式规则复检(30 分钟) 已启用"

    cp -a "$SCRIPT_DIR/systemd/dns-stack-publish.service" /etc/systemd/system/ 2>/dev/null || true
    cp -a "$SCRIPT_DIR/systemd/dns-stack-publish.timer" /etc/systemd/system/ 2>/dev/null || true
    systemctl daemon-reload
    if systemctl is-enabled --quiet dns-stack-publish.timer 2>/dev/null; then
        log_ok "规则自动发布已启用(每 6 小时)"
    else
        log_warn "规则自动发布**未启用**(它会向公开 GitHub 仓库 push)"
        log_warn "  确认 deploy key 已配好后执行: systemctl enable --now dns-stack-publish.timer"
        log_warn "  不启用的话，分类结果不会传到国内服务器"
    fi
}

step16_write_config() {
    log_info "[16/17] 核对基础配置..."
    ensure_config_env

    if [[ "$ROLE" != "global-builder" ]]; then
        return 0
    fi

    if [[ ! -f "$SECRETS_DIR/github_deploy_key" ]]; then
        log_warn "  未检测到 GitHub Deploy Key，正在生成..."
        ssh-keygen -t ed25519 -N '' -C 'dns-stack-github-deploy' -f "$SECRETS_DIR/github_deploy_key" >/dev/null
        chmod 0600 "$SECRETS_DIR/github_deploy_key" "$SECRETS_DIR/github_deploy_key.pub"
        log_warn "  请把下面的公钥添加到 GitHub 仓库 Deploy Keys(勾选 Allow write access):"
        cat "$SECRETS_DIR/github_deploy_key.pub"
    else
        log_info "  GitHub Deploy Key 已存在，跳过生成"
    fi
}

step17_firewall_note() {
    if [[ "$ROLE" == "cn-resolver" ]]; then
        log_info "[17/17] 本机无本地过滤防火墙，边界放行由云安全组/边界防火墙负责，需要放行:"
        log_info "        TCP+UDP $(cfg_or_default DOH_PORT 443)  (DoH / DoH3)"
        log_info "        TCP+UDP $(cfg_or_default DOT_PORT 853)  (DoT / DoQ)"
        log_warn "  安装脚本**不会**修改任何防火墙规则，请自行确认云安全组/边界防火墙已放行上述端口"
    else
        log_info "[17/17] 规则构建节点不需要开放额外公网端口(不修改现有防火墙规则)"
    fi
}

main() {
    step1_check_env
    step2_role
    step3_backup_existing
    step5_create_dirs
    step6_install_deps

    ensure_config_env
    if [[ "$ROLE" == "cn-resolver" ]]; then
        ensure_tls_cert
    fi

    step7_deploy_unbound
    step9_placeholder_db

    if [[ "$ROLE" == "cn-resolver" ]]; then
        step8_deploy_mosproxy
        step10_deploy_collector
    else
        step10_deploy_classifier
    fi

    step11_deploy_helper
    step12_deploy_panel
    step13_deploy_shell

    if [[ "$ROLE" == "global-builder" ]]; then
        step14_confirm_publish
    fi

    step15_cert
    step16_write_config

    step_backup_timer
    step_logrotate
    if [[ "$ROLE" == "cn-resolver" ]]; then
        step_cn_timers
        step_sysctl
        step_recursive_routing
    else
        step_global_timers
    fi

    step17_firewall_note

    echo
    log_ok "========== 安装完成 =========="
    echo "角色: ${ROLE}"
    echo "日常管理请使用: sudo dns-stack"
    echo
    dns-stack health || true
}

main "$@"
