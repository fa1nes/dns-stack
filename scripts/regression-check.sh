#!/usr/bin/env bash
set -uo pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

C_G=$'\033[32m'; C_R=$'\033[31m'; C_D=$'\033[2m'; C_0=$'\033[0m'
PASS=0; FAIL=0; SKIP=0

ok()   { printf "  ${C_G}✓${C_0} %s\n" "$1"; PASS=$((PASS+1)); }
bad()  { printf "  ${C_R}✗${C_0} %s${C_D}%s${C_0}\n" "$1" "${2:+  → $2}"; FAIL=$((FAIL+1)); }
skip() { printf "  ${C_D}–${C_0} %s${C_D}%s${C_0}\n" "$1" "${2:+  ($2)}"; SKIP=$((SKIP+1)); }
sec()  { printf "\n${C_D}── %s ${C_0}\n" "$1"; }

a() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
code_only() { grep -vE '^[[:space:]]*#' "$1" 2>/dev/null; }
_grep_code() { local f="$1" p="$2" body; body="$(code_only "$f")"; grep -qE -- "$p" <<<"$body"; }

has() { local d="$1" f="$2" p="$3"
        if [[ ! -e "$f" ]]; then bad "$d" "文件不存在: $f"
        elif _grep_code "$f" "$p"; then ok "$d"
        else bad "$d" "未在 $(basename "$f") 的代码中找到预期内容"; fi; }
hasnt() { local d="$1" f="$2" p="$3"
          if [[ ! -e "$f" ]]; then bad "$d" "文件不存在: $f"
          elif _grep_code "$f" "$p"; then bad "$d" "代码中仍存在应被移除的内容"
          else ok "$d"; fi; }

SOURCE_MODE=0
if [[ -n "${DNS_STACK_SOURCE_ROOT:-}" ]]; then
    SOURCE_MODE=1
    SRC="$(cd "$DNS_STACK_SOURCE_ROOT" && pwd)"
    CONFIG_FILE="${CONFIG_FILE:-$SRC/config.example.env}"
    STATE_DIR="${STATE_DIR:-$SRC/.source-state}"
    CLI="$SRC/bin/dns-stack"
    ROLE="${DNS_STACK_ROLE:-source}"
else
    CONFIG_FILE="${CONFIG_FILE:-/etc/dns-stack/config.env}"
    STATE_DIR="${STATE_DIR:-/var/lib/dns-stack}"
    SRC="${DNS_STACK_ROOT:-/opt/dns-stack/dns-stack}"
    CLI="${DNS_STACK_CLI:-/usr/local/bin/dns-stack}"
    ROLE="$(grep -E '^ROLE=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2- || echo unknown)"
fi
WEB="$SRC/web"
GO_BIN="${DNS_STACK_GO_BIN:-/opt/dns-stack/bin/dns-stack-go}"

echo "dns-stack 回归校验 · 角色: ${ROLE} · 源码模式: ${SOURCE_MODE} · $(date '+%Y-%m-%d %H:%M:%S')"

sec "运行时无 Python(2026-09-10 起的硬约束)"
STRAY_PY="$(find "$SRC" -name '*.py' -not -path '*/.git/*' -not -path '*/.deploy/*' \
            -not -path '*/.tmp/*' -not -path '*/.memory-archive/*' 2>/dev/null | head -5)"
[[ -z "$STRAY_PY" ]] && ok "源码树中没有 .py 文件" \
    || bad "源码树中仍有 Python" "$(tr '\n' ' ' <<<"$STRAY_PY")"

PY_CALLS=""
for f in "$SRC"/scripts/*.sh "$SRC"/migration/*.sh "$SRC"/bin/dns-stack \
         "$SRC"/install.sh "$SRC"/uninstall.sh; do
    [[ -f "$f" ]] || continue
    code_only "$f" | grep -qE '(^|[^a-zA-Z_-])python3?[[:space:]]' && PY_CALLS="${PY_CALLS} $(basename "$f")"
done
[[ -z "$PY_CALLS" ]] && ok "生产脚本不再调用 python3" || bad "仍有脚本调用 python3" "$PY_CALLS"

hasnt "systemd 单元不再指向 venv" "$SRC/systemd/mosproxy.service" 'venv'
a "helper 主单元直接跑 Go 二进制(drop-in 脚手架已退场)" \
    grep -q 'ExecStart=/opt/dns-stack/bin/dns-stack-go helper' "$SRC/systemd/dns-stack-helper.service"
a "面板主单元直接跑 Go 二进制" \
    grep -q 'ExecStart=/opt/dns-stack/bin/dns-stack-go panel' "$SRC/systemd/dns-stack-panel.service"
a "已不再随仓库提供 Go 化 drop-in" \
    bash -c "! ls '$SRC'/systemd/*.service.d-go-*.conf >/dev/null 2>&1"

sec "Go 侧构建与测试(取代此前上百条「某标识符存在于某文件」的断言)"
GO_CMD="$(command -v go 2>/dev/null || echo /usr/local/go/bin/go)"
if [[ -x "$GO_CMD" && -f "$SRC/go.mod" ]]; then
    ( cd "$SRC" && CGO_ENABLED=0 "$GO_CMD" build ./... ) >/dev/null 2>&1 \
        && ok "go build ./... 通过" || bad "go build ./... 失败"
    ( cd "$SRC" && CGO_ENABLED=0 "$GO_CMD" vet ./... ) >/dev/null 2>&1 \
        && ok "go vet ./... 通过" || bad "go vet ./... 失败"
    ( cd "$SRC" && CGO_ENABLED=0 "$GO_CMD" test ./... -count=1 ) >/dev/null 2>&1 \
        && ok "go test ./... 通过" || bad "go test ./... 失败" "逐条看: cd $SRC && go test ./..."
    UNFMT="$( cd "$SRC" && "$(dirname "$GO_CMD")/gofmt" -l cmd internal web 2>/dev/null )"
    [[ -z "$UNFMT" ]] && ok "gofmt 无待格式化文件" || bad "有未格式化的 Go 文件" "$UNFMT"
    UNTESTED=""
    for d in "$SRC"/internal/*/; do
        [[ -d "$d" ]] || continue
        [[ "$(basename "$d")" == "resolvetest" ]] && continue
        compgen -G "$d*_test.go" >/dev/null || UNTESTED="${UNTESTED} $(basename "$d")"
    done
    [[ -z "$UNTESTED" ]] && ok "每个 internal 包都有测试" \
        || bad "以下 internal 包没有任何测试:${UNTESTED}" "删掉 Python 参照后，测试是唯一的正确性证据"
else
    skip "Go 构建与测试" "本机无 Go 工具链"
fi

sec "换行符与可执行位(部署后才暴露的一类)"
CRLF_HITS=0
for f in "$CLI" "$SRC"/scripts/*.sh "$SRC"/migration/*.sh \
         "$SRC"/install.sh "$SRC"/uninstall.sh; do
    [[ -f "$f" ]] || continue
    grep -qU $'\r' "$f" 2>/dev/null && { CRLF_HITS=$((CRLF_HITS+1)); echo "      含 CRLF: $f"; }
done
[[ "$CRLF_HITS" -eq 0 ]] && ok "所有 shell 脚本均为 LF 换行" \
    || bad "有 ${CRLF_HITS} 个脚本含 CRLF" "会导致 bash\\r 无法执行"

if [[ "$SOURCE_MODE" -eq 1 ]]; then
    has "install.sh 会补 dns-stack 命令可执行位" \
        "$SRC/install.sh" 'chmod \+x .*dns-stack|/usr/local/bin/dns-stack'
else
    a "dns-stack 命令具备可执行位" test -x "$CLI"
    a "Go 二进制具备可执行位" test -x "$GO_BIN"
    if [[ -f "$CLI" && -f "$SRC/bin/dns-stack" ]]; then
        cmp -s "$CLI" "$SRC/bin/dns-stack" \
            && ok "安装 dns-stack 与源码树内容一致" \
            || bad "安装 dns-stack 与源码树漂移" "先按部署铁律逐文件同步"
    else
        bad "安装 dns-stack 与源码树一致性无法检查" "缺少安装 CLI 或源码副本"
    fi
    if [[ -f "$GO_BIN.sha256" ]]; then
        WANT="$(awk '{print $1}' "$GO_BIN.sha256")"
        GOT="$(sha256sum "$GO_BIN" 2>/dev/null | awk '{print $1}')"
        [[ -n "$WANT" && "$WANT" == "$GOT" ]] \
            && ok "Go 二进制与安装时记录的 sha256 一致" \
            || bad "Go 二进制被替换过或记录缺失" "期望 ${WANT:-无} 实际 ${GOT:-无}"
    else
        skip "Go 二进制指纹核对" "缺少 $GO_BIN.sha256"
    fi
fi

sec "配置与权限(静默降级的重灾区)"
if [[ "$SOURCE_MODE" -eq 1 ]]; then
    skip "生产配置与 secrets 权限检查" "源码模式不读取 /etc/dns-stack"
elif id -u dns-stack-panel >/dev/null 2>&1; then
    PERM="$(stat -c '%a %U:%G' "$CONFIG_FILE" 2>/dev/null)"
    [[ "$PERM" == "640 root:dns-stack-panel" ]] \
        && ok "config.env 权限 640 root:dns-stack-panel" \
        || bad "config.env 权限异常" "实际=${PERM}，面板将读不到配置"
    SPERM="$(stat -c '%a %U:%G' /etc/dns-stack/secrets 2>/dev/null)"
    [[ "$SPERM" == "710 root:dns-stack-panel" ]] \
        && ok "secrets 目录权限 710 root:dns-stack-panel" \
        || bad "secrets 目录权限异常" "实际=${SPERM}"
else
    skip "面板用户权限检查" "dns-stack-panel 用户不存在"
fi

KEYS="$(grep -cE '^[A-Za-z_][A-Za-z0-9_]*=' "$CONFIG_FILE" 2>/dev/null || true)"; KEYS="${KEYS:-0}"
[[ "$KEYS" -ge 20 ]] && ok "config.env 配置项完整(${KEYS} 项)" \
                     || bad "config.env 仅 ${KEYS} 项，疑似残缺" "重跑 install.sh 会自动补齐"

sec "面板前端(前端没有单元测试，grep 是唯一判据)"
hasnt "前端不再依赖服务端渲染的 ?v= 指纹" "$WEB/index.html" 'panel\.(css|js)\?v='
has "分流数据集用「直连」而非易误读的「墙内」" "$WEB/index.html" '>直连域名<'
has "界面写明清屏不等于清服务器日志" "$WEB/index.html" '只清当前显示，不动服务器日志'
has "面板会在有流量却零事件入库时报采集中断" "$WEB/assets/panel.js" '采集已停'
has "分流卡把大陆权威集合纳入判据" "$WEB/assets/panel.js" 'cn_authority_count'
has "限流拒绝非 0 时面板会告警" "$WEB/assets/panel.js" '次查询被限流拒绝'
has "面板展示递归出口归属" "$WEB/assets/panel.js" '出口归属'
has "面板判定规则同步链路是否中断" "$WEB/assets/panel.js" 'SYNC_STALE_SEC'
a "前端资源已编进二进制(改前端必须重建)" test -f "$SRC/web/embed.go"

sec "机密与脱敏"
if [[ -f /var/log/dns-stack/helper.log ]]; then
    grep -qE '"password": "[^["]' /var/log/dns-stack/helper.log 2>/dev/null \
        && bad "helper.log 中发现疑似明文密码" \
        || ok "helper.log 中无明文密码"
else
    skip "helper.log 明文密码检查" "日志文件不存在"
fi
if [[ -S /run/dns-stack/helper.sock && -x "$GO_BIN" ]]; then
    LEAK="$("$GO_BIN" helper-probe 2>/dev/null || echo -1)"
    case "$LEAK" in
        0)  ok "日志脱敏有效(无完整客户端 IP)" ;;
        -1) skip "日志脱敏抽查" "helper 未响应" ;;
        *)  bad "日志中发现 ${LEAK} 个完整全局 IPv4" "多为服务器自身地址，请人工确认" ;;
    esac
else
    skip "日志脱敏抽查" "helper socket 不可用"
fi

_go_units() {   # <文件> <变量名> —— 取该 Go 变量字面量块内的全部单元名
    sed -n "/$2 = /,/^}/p" "$1" 2>/dev/null \
        | grep -oE '"dns-stack[A-Za-z0-9@._-]*"' | tr -d '"' | sort -u
}
PANEL_UNITS="$( { _go_units "$SRC/internal/panel/services.go" 'cnUnits'
                  _go_units "$SRC/internal/panel/services.go" 'globalUnits'; } | sort -u | grep -v '^$')"
HELPER_UNITS="$(_go_units "$SRC/internal/helper/ops.go" 'allowedUnits')"
if [[ -z "${PANEL_UNITS//[[:space:]]/}" || -z "${HELPER_UNITS//[[:space:]]/}" ]]; then
    bad "取不到面板或 helper 的单元清单" "变量名是否改过？判据自身失效比结果为 0 更危险"
else
    MISSING="$(comm -23 <(printf '%s\n' "$PANEL_UNITS") <(printf '%s\n' "$HELPER_UNITS") | tr '\n' ' ')"
    [[ -z "${MISSING// /}" ]] \
        && ok "面板监视的单元 helper 全部放行($(grep -c . <<<"$PANEL_UNITS") 个)" \
        || bad "helper 白名单缺少面板要监视的单元" "$MISSING"
    GHOST=""
    for u in $PANEL_UNITS; do
        [[ -f "$SRC/systemd/$u.service" || -f "$SRC/systemd/$u.timer" ]] || GHOST="${GHOST} $u"
    done
    [[ -z "$GHOST" ]] && ok "面板监视的单元都有对应的 systemd 文件" \
        || bad "面板监视了不存在的单元:${GHOST}" "会永远显示「未运行」"
fi

sec "部署与迁移"
MISSING=""
for f in install.sh uninstall.sh config.example.env systemd scripts migration cmd internal web; do
    [[ -e "$SRC/$f" ]] || MISSING="${MISSING} $f"
done
[[ -z "$MISSING" ]] && ok "迁移用源码树完整" || bad "源码树缺少:${MISSING}" "dns-stack migrate 会失败"

has "migrate 首次连接自动接受主机密钥" "$SRC/migration/migrate.sh" 'StrictHostKeyChecking=accept-new'
has "import 先停写入者再替换数据库" "$SRC/migration/import.sh" 'DB_WRITERS'
has "import 清理陈旧的 -wal/-shm" "$SRC/migration/import.sh" 'wal.*shm|shm.*wal'
has "import 导入后自检数据库完整性" "$SRC/migration/import.sh" 'integrity_check'
has "import 还原 config.env 属组" "$SRC/migration/import.sh" 'chgrp dns-stack-panel .*CONFIG_FILE'
has "import 健康检查覆盖面板" "$SRC/migration/import.sh" 'RESTART_UNITS'
has "显式数据库迁移先做一致性备份" "$SRC/scripts/migrate-databases.sh" '\.backup'
hasnt "install.sh 不再钉死发行版专有版本号" "$SRC/install.sh" 'unbound=1\.13|age=1\.0\.0-1ubuntu'
has "install.sh 记录实际安装版本" "$SRC/install.sh" 'record_installed_versions'
has "install.sh 保证配置先于使用就位" "$SRC/install.sh" 'ensure_config_env'
has "install.sh 保证证书先于 mosproxy 就位" "$SRC/install.sh" 'ensure_tls_cert'
has "装机集成递归出口分流" "$SRC/install.sh" 'step_recursive_routing'
hasnt "面板部署不再递归夺走动态目录属组" "$SRC/install.sh" 'chgrp -R dns-stack-panel "\$STATE_DIR"'
has "mosproxy 二进制必须匹配补丁指纹" "$SRC/install.sh" 'mosproxy_binary_matches.*expected'
hasnt "安装器不再无条件保留旧 mosproxy" "$SRC/install.sh" '已存在 mosproxy 二进制，保留不动'
has "迁移只携带验证过的 mosproxy" "$SRC/migration/migrate.sh" 'mosproxy_artifact_matches'
has "源码原地重跑不会删除自身" "$SRC/install.sh" 'source_root.*target_root'
hasnt "安装器不在生产机编译 Go(规格不受控，2026-09-07 就是这么 OOM 的)" "$SRC/install.sh" 'go build'
has "Go 二进制改为下载 CI 产物" "$SRC/install.sh" 'binaries-latest'
has "下载后核对 sha256" "$SRC/install.sh" 'sha256sum'
has "CI 断言 Linux 产物是静态链接(HK 是 Alpine/musl)" \
    "$SRC/.github/workflows/build.yml" 'statically linked'
has "CI 会发布滚动构建供生产下载" "$SRC/.github/workflows/build.yml" 'binaries-latest'

UNCOVERED=""
for u in $(ls /etc/systemd/system/ 2>/dev/null | grep -E '^dns-stack' | sed 's/\.\(service\|timer\)$//' | sort -u); do
    grep -q "$u" "$SRC/uninstall.sh" 2>/dev/null || UNCOVERED="${UNCOVERED} $u"
done
[[ -z "$UNCOVERED" ]] && ok "卸载脚本覆盖全部已安装单元" || bad "卸载遗漏:${UNCOVERED}"
has "卸载支持 --dry-run" "$SRC/uninstall.sh" 'dry-run'
has "卸载会警告备份密钥不可逆" "$SRC/uninstall.sh" '永久无法解密'
has "CLI 分发层不误报未预期错误" "$CLI" 'dispatch "\$@" \|\| exit'

sec "数据采集与定时任务"
hasnt "preflight 不写生产数据库" "$SRC/scripts/preflight.sh" 'DELETE FROM domains'
has "preflight 验证国内域名落在大陆节点" "$SRC/scripts/preflight.sh" '国内域名解析到大陆节点'
has "preflight 用香港递归器做污染对照" "$SRC/scripts/preflight.sh" '10\.100\.0\.3'
has "preflight 把境外域名解析到大陆 IP 判为污染" "$SRC/scripts/preflight.sh" '疑似污染'
has "preflight 区分冷启动窗口与真实故障" "$SRC/scripts/preflight.sh" '冷启动窗口'
has "preflight 提醒边界放行由云安全组负责" "$SRC/scripts/preflight.sh" '云安全组已放行'
has "preflight 探测跟随实际 DoH 路径" "$SRC/scripts/preflight.sh" 'DOH_PATH_CUR'
has "preflight 检查 conntrack 运行时水位" "$SRC/scripts/preflight.sh" 'nf_conntrack_count'
has "证书续签显式指定 acme.sh home" "$SRC/scripts/renew-cert.sh" '--home "\$ACME_HOME"'

for db in "$STATE_DIR/collector.db" "$STATE_DIR/classifier.db"; do
    [[ -f "$db" ]] || continue
    R="$(sqlite3 "$db" 'PRAGMA integrity_check;' 2>&1 | head -1)"
    [[ "$R" == "ok" ]] && ok "$(basename "$db") 完整性正常" || bad "$(basename "$db") 完整性异常" "$R"
done

for timer in dns-stack-reference-data dns-stack-classify dns-stack-verify \
             dns-stack-publish dns-stack-collect-polluted dns-stack-sync-rules \
             dns-stack-renew-cert; do
    has "$timer 晚启动仍会首次触发" "$SRC/systemd/$timer.timer" '^OnActiveSec='
done

if [[ "$SOURCE_MODE" -eq 1 ]]; then
    has "自动备份 timer 单元存在" "$SRC/systemd/dns-stack-backup.timer" '^\[Timer\]'
else
    a "自动备份 timer 单元存在" test -f /etc/systemd/system/dns-stack-backup.timer
    a "自动备份 timer 已启用" systemctl is-enabled --quiet dns-stack-backup.timer
    a "自动备份 timer 运行中" systemctl is-active --quiet dns-stack-backup.timer
    BK_KEEP="$(grep -E '^BACKUP_RETENTION_DAILY=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)"
    if [[ "$BK_KEEP" =~ ^[0-9]+$ && "$BK_KEEP" -ge 1 && "$BK_KEEP" -le 10 ]]; then
        ok "备份保留份数合理($BK_KEEP 份)"
    else
        bad "备份保留份数异常" "当前=${BK_KEEP:-未设置}，应为 1-10"
    fi
fi

sec "规则流水线的编排(shell 层，没有单元测试覆盖)"
has "同步端固定字节序以保持规则哈希一致" "$SRC/scripts/sync-rules.sh" 'export LC_ALL=C'
has "同步端清空任一非空规则必须人工确认" "$SRC/scripts/sync-rules.sh" '从 \$oc 条降为空集'
has "规则同步按版本择新" "$SRC/scripts/sync-rules.sh" 'gen_at'
has "拒绝比本地更旧的规则" "$SRC/scripts/sync-rules.sh" 'stale_skipped'
has "同步端要求完整四文件包" "$SRC/scripts/sync-rules.sh" 'cn-ip-cidr\.txt.*polluted-ip-cidr\.txt'
has "冷启动包必须人工显式接受" "$SRC/scripts/sync-rules.sh" 'accept-cold-start'
has "全空 CIDR 包必须独立显式接受" "$SRC/scripts/sync-rules.sh" 'accept-full-reset'
has "规则清洗改由 Go 子命令" "$SRC/scripts/sync-rules.sh" 'rules check-domains'
has "direct4 改由 Go 子命令生成" "$SRC/scripts/update-chnroute.sh" 'chnroute'
has "大陆 IP 表取自 APNIC 一手委派记录" "$SRC/scripts/update-chnroute.sh" 'delegated-apnic-latest'
has "集合护栏用覆盖地址数而非会波动的条目数" "$SRC/scripts/update-chnroute.sh" 'MIN_ADDRESSES'
has "集合产物权限显式放开(mktemp 默认 0600 会让面板读不到)" \
    "$SRC/scripts/update-chnroute.sh" 'chmod 0644'
hasnt "chnroute 不解除 EXIT trap 后手写清单" "$SRC/scripts/update-chnroute.sh" '^trap - EXIT$'
has "污染证据改由 Go 聚合" "$SRC/scripts/collect-polluted-ip.sh" 'polluted-evidence'
has "ECS 白名单为空时不覆盖" "$SRC/scripts/update-cn-authority.sh" 'ECS 白名单为空'
has "墙内域名判据：任一级权威在大陆即全程直连" "$SRC/scripts/update-cn-authority.sh" 'cn_authority'
has "人工区域取不到权威时不中止且告警" "$SRC/scripts/update-cn-authority.sh" 'manual_unresolved'
has "人工区域 NS 截断用 awk 不用 head" "$SRC/scripts/update-cn-authority.sh" "awk 'NR<=8'"
hasnt "cn-authority 不解除 EXIT trap 后手写清单" "$SRC/scripts/update-cn-authority.sh" '^trap - EXIT$'
has "归属库校验走 Go 子命令" "$SRC/scripts/update-geoip.sh" 'geoip-verify --kind'
has "拉取端会取 DB-IP 交叉库" "$SRC/scripts/update-geoip.sh" 'dbip-city\.mmdb'
has "拉取端会取 IPinfo 交叉库" "$SRC/scripts/update-geoip.sh" 'ipinfo-lite\.mmdb'
has "拉取端报出可交叉源数量而非只报下载成功数" "$SRC/scripts/update-geoip.sh" '多源交叉可用源'
has "update-geoip 的 EXIT trap 显式返回 0" "$SRC/scripts/update-geoip.sh" 'return 0'
has "重分类期间会禁用自动发布" "$CLI" 'disable --now dns-stack-publish.timer'
has "分类、复检与发布使用同一进程锁" "$SRC/systemd/dns-stack-verify.service" 'dns-stack-classifier\.lock'
has "分类流水线一次跑完(共享 direct4/PSL/解析客户端)" \
    "$SRC/systemd/dns-stack-classify.service" 'classify pipeline'

sec "递归出口分流(nft 层，改错会静默走错方向)"
has "分流链用 route hook 才会触发重新路由" \
    "$SRC/scripts/setup-recursive-routing.sh" 'type route hook output'
has "分流链正向匹配 uid(排除法会吞掉隧道自身的握手包)" \
    "$SRC/scripts/setup-recursive-routing.sh" 'meta skuid'
has "隧道端点纳入直连保护" "$SRC/scripts/setup-recursive-routing.sh" 'NFT_ENDPOINT_SET'
has "出隧道包改写源地址(否则被对端 ACL 拒收)" \
    "$SRC/scripts/setup-recursive-routing.sh" 'masquerade'
has "wg0.conf 缺 Table=off 时拒绝继续" "$SRC/scripts/setup-recursive-routing.sh" '开机即失控'
has "隧道故障默认 fail-closed 不回落直连" \
    "$SRC/scripts/setup-recursive-routing.sh" 'TUNNEL_FAIL_MODE'
has "隧道重建后清 infra cache(否则恢复要等 infra-host-ttl 到期)" \
    "$SRC/systemd/dns-stack-recursive-routing.service" 'flush_infra'
a "分流看门狗脚本存在" test -f "$SRC/scripts/routing-watchdog.sh"
a "分流看门狗 timer 存在" test -f "$SRC/systemd/dns-stack-routing-watchdog.timer"
has "install.sh 启用分流看门狗" "$SRC/install.sh" 'dns-stack-routing-watchdog\.timer'
has "install.sh 启用 ECS 分片定时任务" "$SRC/install.sh" 'dns-stack-ecs-zone'

sec "Unbound / mosproxy 模板"
has "Unbound 启用缓存投毒检测" "$SRC/unbound/unbound.template.conf" '^\s*unwanted-reply-threshold:'
has "Unbound 记录 DNSSEC 校验失败" "$SRC/unbound/unbound.template.conf" '^\s*val-log-level:'
has "Unbound 启用 so-reuseport" "$SRC/unbound/unbound.template.conf" '^\s*so-reuseport:\s*yes'
has "Unbound 请求放大的 socket 缓冲" "$SRC/unbound/unbound.template.conf" '^\s*so-rcvbuf:'
has "无响应权威的探测频率已放宽" "$SRC/unbound/unbound.template.conf" 'infra-host-ttl: 3600'
has "Unbound 不把 ECS 转发给所有权威" \
    "$SRC/unbound/unbound.template.conf" 'client-subnet-always-forward:\s*no'
check_ip6_disabled() {
    local file="$1" no yes
    no="$(grep -Ec '^\s*do-ip6:\s*no\s*$' "$file" 2>/dev/null || true)"
    yes="$(grep -Ec '^\s*do-ip6:\s*yes\s*$' "$file" 2>/dev/null || true)"
    [[ "$no" -eq 1 && "$yes" -eq 0 ]]
}
a "Unbound 默认禁止 IPv6 出站" check_ip6_disabled "$SRC/unbound/unbound.template.conf"
_IP6_NEGATIVE="$(mktemp)"
sed 's/^\(\s*do-ip6:\s*\)no\s*$/\1yes/' "$SRC/unbound/unbound.template.conf" > "$_IP6_NEGATIVE"
if check_ip6_disabled "$_IP6_NEGATIVE"; then
    bad "Unbound IPv6 阴性对照未失败" "do-ip6 改回 yes 后校验仍通过"
else
    ok "Unbound IPv6 阴性对照按预期失败"
fi
rm -f "$_IP6_NEGATIVE"

has "mosproxy 启用 ECS" "$SRC/mosproxy/config.template.yaml" '^ecs:'
has "mosproxy 兜底交给本机递归" "$SRC/mosproxy/config.template.yaml" 'forward: "recursive-lb"'
hasnt "域名名单不再参与 DNS 分流" "$SRC/mosproxy/config.template.yaml" 'tag: "dynamic-lb"'
has "mosproxy 管道启用 pipefail(否则崩溃被判成正常退出)" \
    "$SRC/systemd/mosproxy.service" 'bash -o pipefail'
has "mosproxy 用 Restart=always(DNS 不该有正常退出这个状态)" \
    "$SRC/systemd/mosproxy.service" '^Restart=always'
has "mosproxy 有重启风暴护栏" "$SRC/systemd/mosproxy.service" '^StartLimitBurst='
has "mosproxy 由 fork 发布而非本机编译" "$SRC/versions.lock" '"build_method": "fork release"'
hasnt "install.sh 不再在生产机编译 mosproxy" "$SRC/install.sh" 'build-mosproxy.sh'
a "mosproxy 产物指纹校验(含篡改阴性对照)" bash "$SRC/scripts/tests/test-mosproxy-artifact.sh"

sec "内核参数与日志"
has "内核放开 rmem_max 以配合 so-rcvbuf" "$SRC/docs/sysctl-cn.conf" '^net\.core\.rmem_max'
has "conntrack UDP 超时已收紧" "$SRC/docs/sysctl-cn.conf" '^net\.netfilter\.nf_conntrack_udp_timeout'
has "conntrack TCP established 超时已收紧" \
    "$SRC/docs/sysctl-cn.conf" '^net\.netfilter\.nf_conntrack_tcp_timeout_established'
has "扩大的临时端口范围排除了固定监听端口" \
    "$SRC/docs/sysctl-cn.conf" '^net\.ipv4\.ip_local_reserved_ports'
has "install.sh 部署内核参数" "$SRC/install.sh" 'step_sysctl'
a "logrotate 配置文件存在" test -f "$SRC/docs/logrotate-dns-stack.conf"
has "install.sh 会安装 logrotate 配置" "$SRC/install.sh" 'step_logrotate'
has "logrotate 让 unbound 重开日志(否则轮转后写进旧 inode)" \
    "$SRC/docs/logrotate-dns-stack.conf" 'log_reopen'
has "logrotate 保持 unbound 日志属主" \
    "$SRC/docs/logrotate-dns-stack.conf" 'create 0644 unbound unbound'
has "uninstall 会清理 logrotate 规则" "$SRC/uninstall.sh" '/etc/logrotate.d/dns-stack'
has "备份函数库自带 pipefail" "$SRC/scripts/backup-common.sh" '^set -o pipefail'
has "产物校验函数库自带 pipefail" "$SRC/scripts/mosproxy-artifact-common.sh" '^set -o pipefail'
has "备份体积骤降会告警" "$SRC/scripts/backup.sh" '本次备份体积仅为上一份的'
has "dns-stack 的 EXIT trap 显式返回 0" "$CLI" 'return 0'
has "health 检查失败单元" "$CLI" 'state=failed'
has "健康检查独立探活降级备份" "$CLI" '降级备份就绪'
has "清理域名会说明为何没删" "$CLI" '无需清理'

sec "资源硬上限(2026-09-07 OOM 掀翻整机后加)"
has "ecs-zone 有内存硬上限" "$SRC/systemd/dns-stack-ecs-zone.service" '^MemoryMax='
has "ecs-zone 有 CPU 配额" "$SRC/systemd/dns-stack-ecs-zone.service" '^CPUQuota='
has "geo-cross 有内存硬上限" "$SRC/systemd/dns-stack-geo-cross.service" '^MemoryMax='
has "geo-cross 有 CPU 配额" "$SRC/systemd/dns-stack-geo-cross.service" '^CPUQuota='
has "CI 有规模/性能门禁" "$SRC/.github/workflows/build.yml" 'MAX_RSS_KB'
has "门禁用真实量级的 direct4 而不是玩具数据" \
    "$SRC/.github/workflows/build.yml" 'delegated-apnic-latest'
has "拉不到归属库时门禁明确报 skip 而不是静默通过" \
    "$SRC/.github/workflows/build.yml" '门禁形同虚设'
has "门禁自证过两个方向(判据自己不能只走一条通路)" \
    "$SRC/.github/workflows/build.yml" '门禁自证通过'
hasnt "出二进制不被门禁挡住" "$SRC/.github/workflows/build.yml" 'needs: \[verify, scale-gate\]'
has "权威集合生成排在交叉计算之后" \
    "$SRC/systemd/dns-stack-cn-authority.service" 'dns-stack-geo-cross'
has "分片表生成排在交叉计算之后" \
    "$SRC/systemd/dns-stack-ecs-zone.service" 'dns-stack-geo-cross'
has "geo-cross 单元存在" "$SRC/systemd/dns-stack-geo-cross.timer" '^\[Timer\]'

sec "会 fail-open 的写法扫描"
CNT_FAILOPEN="$(grep -rnE 'grep -[a-zA-Z]*c[a-zA-Z]* [^|]*\|\|[[:space:]]*echo [0-9]' \
    "$SRC/scripts" "$SRC/bin" 2>/dev/null \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' || true)"
[[ -z "$CNT_FAILOPEN" ]] \
    && ok "计数未使用会 fail-open 的 'grep -c || echo N' 写法" \
    || bad "发现 $(printf '%s' "$CNT_FAILOPEN" | grep -c . || true) 处 'grep -c || echo N'" \
           "零匹配时变量会变成 0\\n0，数值比较语法错误并判为假"

a "归属库不被解析运行时引用" \
  bash -c "! grep -rhE 'geoip|geo_lookup' \
      '$SRC/mosproxy' '$SRC/unbound' '$SRC/scripts/setup-recursive-routing.sh' \
      '$SRC/scripts/update-cn-authority.sh' \
      '$SRC/scripts/routing-watchdog.sh' 2>/dev/null \
      | grep -vE '^[[:space:]]*#' | grep -q ."

sec "生产态：多源交叉判据是否真的在生效"
if [[ "$SOURCE_MODE" -eq 1 || "$ROLE" == "global-builder" ]]; then
    skip "多源交叉清单的生产态检查" "只在 CN 解析节点有意义"
else
    DISPUTED_FILE="$STATE_DIR/chnroute/geo-disputed.txt"
    ECS_CONF_CUR="${ECS_CONF_FILE:-/etc/unbound/unbound.conf.d/dns-stack-ecs.conf}"
    a "dns-stack-geo-cross.timer 已启用" systemctl is-enabled --quiet dns-stack-geo-cross.timer
    if [[ ! -f "$DISPUTED_FILE" ]]; then
        bad "多源争议清单不存在" \
            "判据从未产出，收紧完全没生效: systemctl start dns-stack-geo-cross.service"
    else
        GEN_AT="$(grep -m1 '^# generated-at' "$DISPUTED_FILE" 2>/dev/null | awk '{print $3}')"
        GEN_AT="${GEN_AT:-0}"
        AGE_H=$(( ( $(date +%s) - GEN_AT ) / 3600 ))
        if [[ "$GEN_AT" -gt 0 && "$AGE_H" -lt 72 ]]; then
            ok "多源争议清单新鲜(${AGE_H} 小时前)"
        else
            bad "多源争议清单已 ${AGE_H} 小时未更新" \
                "陈旧清单仍会被使用，但反映的是旧的归属数据"
        fi
        DIS_SRC="$(grep -m1 '^# sources' "$DISPUTED_FILE" 2>/dev/null | cut -d' ' -f3-)"
        DIS_N=$(awk -F, '{print NF}' <<<"${DIS_SRC:-}")
        [[ "${DIS_N:-0}" -ge 2 ]] \
            && ok "参与交叉的归属库 ${DIS_N} 个(${DIS_SRC})" \
            || bad "参与交叉的归属库不足 2 个(${DIS_SRC:-无})" \
                   "direct4-audit 会 fail-open，检查 GEOIP_RELEASE_REPO 与 GEOIP_ENABLE_CITY"

        if [[ ! -f "$ECS_CONF_CUR" ]]; then
            skip "ECS 白名单与争议网段交集核对" "缺少 ECS 配置"
        elif [[ ! -x "$GO_BIN" ]]; then
            bad "无法核对 ECS 白名单与争议网段" "缺少 $GO_BIN，判据自身失效比结果为 0 更危险"
        elif ! grep -qE '^[^#]' "$DISPUTED_FILE"; then
            skip "ECS 白名单与争议网段无交集" "本轮没有任何争议网段"
        else
            LEAKS="$(grep -oE 'send-client-subnet:[[:space:]]*[0-9./]+' "$ECS_CONF_CUR" \
                     | awk '{print $2}' \
                     | "$GO_BIN" ipset-check --list "$DISPUTED_FILE" --overlap 2>/dev/null \
                     | awk -F'\t' '$2==1' | grep -c . || true)"
            if [[ ! "$LEAKS" =~ ^[0-9]+$ ]]; then
                bad "无法核对 ECS 白名单与争议网段" "判据自身失效，比结果为 0 更危险"
            elif [[ "$LEAKS" -eq 0 ]]; then
                ok "ECS 白名单与争议网段零交集"
            else
                bad "ECS 白名单仍有 ${LEAKS} 条与争议网段重叠" \
                    "多源判为境外的地址正在收中国客户端子网: 重跑 update-cn-authority.sh"
            fi
        fi
    fi

    if [[ -x "$GO_BIN" ]]; then
        "$GO_BIN" ecs-orphans --max-foreign "${ECS_MAX_FOREIGN_ORPHANS:-9}" >/dev/null 2>&1 \
            && ok "ECS 白名单孤儿在阈值内" \
            || bad "ECS 白名单孤儿超阈值" "详情: $GO_BIN ecs-orphans --list"
    fi

    DP="$(grep -E '^DOH_PATH=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2-)"
    [[ -n "$DP" && "$DP" != "/dns-query" ]] && ok "DoH 已启用私密路径" \
        || bad "DoH 仍是默认路径" "sudo dns-stack doh-path --rotate"
fi

sec "生产态：运行时确实是 Go 二进制"
if [[ "$SOURCE_MODE" -eq 1 ]] || ! command -v systemctl >/dev/null 2>&1; then
    skip "运行时实现核对" "源码模式或无 systemctl"
else
    for pair in "dns-stack-helper:helper" "dns-stack-panel:panel"; do
        unit="${pair%%:*}"; sub="${pair##*:}"
        if systemctl cat "$unit" 2>/dev/null \
            | awk -v want="ExecStart=/opt/dns-stack/bin/dns-stack-go $sub" \
                  '/^ExecStart=/{last=$0} END{exit !(last == want)}'; then
            ok "$unit 由 Go 二进制提供"
        else
            bad "$unit 未运行 Go 二进制" "systemctl cat $unit 看看 ExecStart"
        fi
    done
    if systemctl cat mosproxy 2>/dev/null | grep -q 'dns-stack-go collect consume-stdin'; then
        ok "采集器由 Go 二进制提供"
    else
        bad "采集器未切到 Go 二进制"
    fi
fi

echo
printf "结果: ${C_G}%d 通过${C_0}  ${C_R}%d 失败${C_0}" "$PASS" "$FAIL"
[[ "$SKIP" -gt 0 ]] && printf "  ${C_D}%d 跳过${C_0}" "$SKIP"
echo
if [[ "$FAIL" -gt 0 ]]; then
    echo "存在回归项，请对照上面的 ✗ 逐条处理。"
    exit 1
fi
echo "全部回归项保持修复状态。"
exit 0
