#!/usr/bin/env bash
set -Eeuo pipefail

export LC_ALL=C

CONFIG_FILE="${CONFIG_FILE:-/etc/dns-stack/config.env}"
STATE_DIR="${STATE_DIR:-/var/lib/dns-stack}"
DNS_STACK_BIN="${DNS_STACK_BIN:-/opt/dns-stack/bin/dns-stack-go}"
HISTORY_DIR="$STATE_DIR/rule-history"
SYNC_STATE_DIR="$STATE_DIR/sync-state"
MOSPROXY_API="${MOSPROXY_API:-127.0.0.1:8888}"
FILES=(cn.txt gfw.txt cn-ip-cidr.txt polluted-ip-cidr.txt)
REMOTE_POLLUTED_SNAPSHOT="$SYNC_STATE_DIR/polluted-ip-cidr.remote.txt"
LOCAL_POLLUTED_CIDRS="$SYNC_STATE_DIR/polluted-ip-cidr.local.txt"
LOCAL_POLLUTED_IPS="$STATE_DIR/polluted-ip.txt"
FORCE_DROP=0
ACCEPT_COLD_START=0
ACCEPT_FULL_RESET=0
ACCEPT_IP_RESET=0
RULE_BUNDLE_HISTORY_KEEP="${RULE_BUNDLE_HISTORY_KEEP:-0}"

log_info() { echo "[信息] $*"; }
log_ok()   { echo "[成功] $*"; }
log_warn() { echo "[警告] $*"; }
log_err()  { echo "[错误] $*" >&2; }
die()      { log_err "$1"; exit 1; }

mkdir -p "$HISTORY_DIR" "$SYNC_STATE_DIR"
cfg_get() { [[ -f "$CONFIG_FILE" ]] && grep -E "^$1=" "$CONFIG_FILE" | head -1 | cut -d= -f2- || true; }
configured_history_keep="$(cfg_get RULE_BUNDLE_HISTORY_KEEP)"
[[ -n "$configured_history_keep" ]] && RULE_BUNDLE_HISTORY_KEEP="$configured_history_keep"
[[ "$RULE_BUNDLE_HISTORY_KEEP" =~ ^[0-9]+$ ]] || RULE_BUNDLE_HISTORY_KEEP=0

gen_at() {
    grep -m1 -oE '^#[[:space:]]*generated-at:[[:space:]]*[0-9]+' "$1" 2>/dev/null \
        | grep -oE '[0-9]+' || echo 0
}

bundle_mode() {
    local mode
    mode="$(grep -m1 -oE '^#[[:space:]]*bundle-mode:[[:space:]]*[a-z-]+' "$1" 2>/dev/null \
        | sed -E 's/^#[[:space:]]*bundle-mode:[[:space:]]*//' || true)"
    echo "${mode:-standard}"
}

clean_domain_file() {
    awk '{ sub(/\r$/,""); print tolower($0) }' "$1" | sed 's/\.$//' \
      | grep -vE '^[[:space:]]*(#|$)' | sort -u > "$2"
    "$DNS_STACK_BIN" rules check-domains "$2"
}

clean_cidr_file() {
    "$DNS_STACK_BIN" rules clean-cidr "$1" "$2"
}

validate_cidr_disjoint() {
    "$DNS_STACK_BIN" rules check-disjoint "$1" "$2"
}

merge_polluted_cidrs() {
    local remote_file="$1" output_file="$2"
    if [[ ! -s "$REMOTE_POLLUTED_SNAPSHOT" && ! -s "$LOCAL_POLLUTED_CIDRS" \
          && -s "$STATE_DIR/polluted-ip-cidr.txt" ]]; then
        clean_cidr_file "$STATE_DIR/polluted-ip-cidr.txt" \
            "$SYNC_STATE_DIR/.polluted-ip-cidr.local.txt.new"
        mv -f "$SYNC_STATE_DIR/.polluted-ip-cidr.local.txt.new" \
            "$LOCAL_POLLUTED_CIDRS"
    fi
    "$DNS_STACK_BIN" rules merge-polluted \
        "$remote_file" "$LOCAL_POLLUTED_IPS" "$LOCAL_POLLUTED_CIDRS" "$output_file"
}

validate_bundle() {
    local dir="$1" ts="" mode="" f cur cur_mode
    for f in "${FILES[@]}"; do
        [[ -s "$dir/raw/$f" ]] || return 1
        cur="$(gen_at "$dir/raw/$f")"
        [[ "$cur" -gt 0 ]] || return 1
        [[ -z "$ts" || "$ts" == "$cur" ]] || return 1
        ts="$cur"
        cur_mode="$(bundle_mode "$dir/raw/$f")"
        [[ "$cur_mode" == "standard" || "$cur_mode" == "cold-start" \
           || "$cur_mode" == "full-reset" || "$cur_mode" == "ip-reset" ]] || return 1
        [[ -z "$mode" || "$mode" == "$cur_mode" ]] || return 1
        mode="$cur_mode"
    done
    clean_domain_file "$dir/raw/cn.txt" "$dir/clean/cn.txt" || return 1
    clean_domain_file "$dir/raw/gfw.txt" "$dir/clean/gfw.txt" || return 1
    clean_cidr_file "$dir/raw/cn-ip-cidr.txt" "$dir/clean/cn-ip-cidr.txt" || return 1
    clean_cidr_file "$dir/raw/polluted-ip-cidr.txt" \
        "$dir/clean/polluted-ip-cidr.txt" || return 1
    validate_cidr_disjoint "$dir/clean/cn-ip-cidr.txt" \
        "$dir/clean/polluted-ip-cidr.txt" || return 1
    if [[ "$mode" == "standard" ]]; then
        :
    elif [[ "$mode" == "cold-start" ]]; then
        [[ ! -s "$dir/clean/cn.txt" && ! -s "$dir/clean/gfw.txt" \
           && ! -s "$dir/clean/cn-ip-cidr.txt" \
           && ! -s "$dir/clean/polluted-ip-cidr.txt" ]] || return 1
    elif [[ "$mode" == "full-reset" ]]; then
        [[ ! -s "$dir/clean/cn.txt" && ! -s "$dir/clean/gfw.txt" \
           && ! -s "$dir/clean/cn-ip-cidr.txt" \
           && ! -s "$dir/clean/polluted-ip-cidr.txt" ]] || return 1
    else
        [[ ! -s "$dir/clean/cn-ip-cidr.txt" \
           && ! -s "$dir/clean/polluted-ip-cidr.txt" ]] || return 1
    fi
    "$DNS_STACK_BIN" rules check-overlap "$dir/clean/cn.txt" "$dir/clean/gfw.txt"
    [[ "$?" -eq 0 ]] || return 1
    echo "$ts" > "$dir/generated-at"
    echo "$mode" > "$dir/bundle-mode"
}

backup_current() {
    local dest="$1" f
    mkdir -p "$dest"
    for f in "${FILES[@]}"; do
        if [[ -f "$STATE_DIR/$f" ]]; then
            cp -a "$STATE_DIR/$f" "$dest/$f"
        else
            : > "$dest/.missing-$f"
        fi
    done
    [[ -f "$SYNC_STATE_DIR/last-generated-at" ]] && \
        cp -a "$SYNC_STATE_DIR/last-generated-at" "$dest/generated-at"
    if [[ -f "$SYNC_STATE_DIR/last-bundle-mode" ]]; then
        cp -a "$SYNC_STATE_DIR/last-bundle-mode" "$dest/bundle-mode"
    else
        echo standard > "$dest/bundle-mode"
    fi
    if [[ -f "$REMOTE_POLLUTED_SNAPSHOT" ]]; then
        cp -a "$REMOTE_POLLUTED_SNAPSHOT" "$dest/polluted-ip-cidr.remote.txt"
    else
        : > "$dest/.missing-polluted-ip-cidr.remote.txt"
    fi
    if [[ -f "$LOCAL_POLLUTED_CIDRS" ]]; then
        cp -a "$LOCAL_POLLUTED_CIDRS" "$dest/polluted-ip-cidr.local.txt"
    else
        : > "$dest/.missing-polluted-ip-cidr.local.txt"
    fi
    if [[ -f "$LOCAL_POLLUTED_IPS" ]]; then
        cp -a "$LOCAL_POLLUTED_IPS" "$dest/polluted-ip.local.txt"
    else
        : > "$dest/.missing-polluted-ip.local.txt"
    fi
    return 0
}

restore_bundle() {
    local src="$1" f
    for f in "${FILES[@]}"; do
        if [[ -f "$src/$f" ]]; then
            cp -a "$src/$f" "$STATE_DIR/$f"
        elif [[ -f "$src/.missing-$f" ]]; then
            rm -f "$STATE_DIR/$f"
        fi
    done
    [[ -f "$src/bundle-mode" ]] && \
        cp -a "$src/bundle-mode" "$SYNC_STATE_DIR/last-bundle-mode"
    if [[ -f "$src/polluted-ip-cidr.remote.txt" ]]; then
        cp -a "$src/polluted-ip-cidr.remote.txt" "$REMOTE_POLLUTED_SNAPSHOT"
    elif [[ -f "$src/.missing-polluted-ip-cidr.remote.txt" ]]; then
        rm -f "$REMOTE_POLLUTED_SNAPSHOT"
    elif [[ -f "$src/polluted-ip-cidr.txt" ]]; then
        cp -a "$src/polluted-ip-cidr.txt" "$REMOTE_POLLUTED_SNAPSHOT"
    fi
    if [[ -f "$src/polluted-ip-cidr.local.txt" ]]; then
        cp -a "$src/polluted-ip-cidr.local.txt" "$LOCAL_POLLUTED_CIDRS"
    elif [[ -f "$src/.missing-polluted-ip-cidr.local.txt" ]]; then
        rm -f "$LOCAL_POLLUTED_CIDRS"
    fi
    if [[ -f "$src/polluted-ip.local.txt" ]]; then
        cp -a "$src/polluted-ip.local.txt" "$LOCAL_POLLUTED_IPS"
    elif [[ -f "$src/.missing-polluted-ip.local.txt" ]]; then
        rm -f "$LOCAL_POLLUTED_IPS"
    fi
    curl -fsS --max-time 10 "http://${MOSPROXY_API}/ctl/reload" >/dev/null 2>&1
}

case "${1:-}" in
    --force)
        FORCE_DROP=1
        shift
        ;;
    --accept-cold-start)
        FORCE_DROP=1
        ACCEPT_COLD_START=1
        shift
        ;;
    --accept-full-reset)
        FORCE_DROP=1
        ACCEPT_FULL_RESET=1
        shift
        ;;
    --accept-ip-reset)
        FORCE_DROP=1
        ACCEPT_IP_RESET=1
        shift
        ;;
    --rollback|"") ;;
    *) die "未知参数: $1" ;;
esac
if [[ "$FORCE_DROP" -eq 1 ]]; then
    [[ "$#" -eq 0 ]] || die "人工确认参数后不接受其它参数"
else
    [[ "$#" -le 1 ]] || die "参数过多"
fi

if [[ "${1:-}" == "--rollback" ]]; then
    last="$(find "$HISTORY_DIR" -maxdepth 1 -type d -name 'bundle-[0-9]*' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)"
    [[ -n "$last" ]] || die "没有可回滚的历史规则包"
    before="$(mktemp -d "$HISTORY_DIR/.before-rollback-$(date '+%Y%m%d%H%M%S')-XXXXXX")"
    backup_current "$before"
    current_gen="$(cat "$SYNC_STATE_DIR/last-generated-at" 2>/dev/null || echo 0)"
    if ! restore_bundle "$last"; then
        restore_bundle "$before" || log_err "mosproxy reload 仍失败，请立即检查服务状态"
        rm -rf "$before"
        die "回滚后的 mosproxy reload 失败，已恢复操作前规则文件"
    fi
    rm -rf "$before"
    if [[ -f "$last/generated-at" ]]; then
        cp -a "$last/generated-at" "$SYNC_STATE_DIR/last-generated-at"
    else
        echo 0 > "$SYNC_STATE_DIR/last-generated-at"
    fi
    echo "$current_gen" > "$SYNC_STATE_DIR/rollback-hold-generated-at"
    log_ok "已回滚四个规则文件: $last"
    log_warn "自动同步将等待 generated-at 高于 ${current_gen} 的新版本"
    exit 0
fi

RAW_BASE="$(cfg_get GITHUB_RAW_BASE)"
MIRROR_1="$(cfg_get GITHUB_MIRROR_1)"
MIRROR_2="$(cfg_get GITHUB_MIRROR_2)"
GITHUB_REPOSITORY="$(cfg_get GITHUB_REPOSITORY)"
GITHUB_BRANCH="$(cfg_get GITHUB_BRANCH)"
GITHUB_BRANCH="${GITHUB_BRANCH:-main}"
[[ -n "$RAW_BASE" ]] || die "GITHUB_RAW_BASE 未配置"

PINNED_BASE=""
if [[ "$ACCEPT_COLD_START" -eq 1 || "$ACCEPT_FULL_RESET" -eq 1 \
      || "$ACCEPT_IP_RESET" -eq 1 ]] \
   && [[ "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
   && [[ "$GITHUB_BRANCH" =~ ^[A-Za-z0-9._/-]+$ ]]; then
    commit_sha="$(
        curl -fsSL --max-time 20 \
            "https://api.github.com/repos/${GITHUB_REPOSITORY}/commits/${GITHUB_BRANCH}" \
        | "$DNS_STACK_BIN" rules json-field sha \
        2>/dev/null || true
    )"
    if [[ "$commit_sha" =~ ^[0-9a-fA-F]{40}$ ]]; then
        PINNED_BASE="https://raw.githubusercontent.com/${GITHUB_REPOSITORY}/${commit_sha}"
        log_info "人工重置流程优先校验 Git commit: ${commit_sha:0:12}"
    else
        log_warn "无法解析最新 Git commit，将继续使用配置的三个规则源"
    fi
fi

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
BEST_DIR=""; BEST_TS=-1; idx=0
for base in "$PINNED_BASE" "$RAW_BASE" "$MIRROR_1" "$MIRROR_2"; do
    [[ -n "$base" ]] || continue
    idx=$((idx+1)); dir="$WORK/source-$idx"; mkdir -p "$dir/raw" "$dir/clean"
    ok=1
    for f in "${FILES[@]}"; do
        curl -fsSL --max-time 20 "$base/$f" -o "$dir/raw/$f" 2>/dev/null || { ok=0; break; }
    done
    [[ "$ok" -eq 1 ]] || { log_warn "规则包下载失败: $base"; continue; }
    validate_bundle "$dir" || { log_warn "规则包校验失败或四文件版本不一致: $base"; continue; }
    ts="$(cat "$dir/generated-at")"; log_ok "候选规则包: $base (版本 $ts)"
    if [[ "$ts" -gt "$BEST_TS" ]]; then BEST_TS="$ts"; BEST_DIR="$dir"; fi
done

if [[ -z "$BEST_DIR" ]]; then
    log_warn "所有来源均失败，保留当前四文件不变"
    echo "$(date -u '+%FT%TZ') bundle_download_failed" >> "$SYNC_STATE_DIR/history.log"
    exit 0
fi

BEST_MODE="$(cat "$BEST_DIR/bundle-mode")"
prev="$(cat "$SYNC_STATE_DIR/last-generated-at" 2>/dev/null || echo 0)"
last_mode="$(cat "$SYNC_STATE_DIR/last-bundle-mode" 2>/dev/null || echo standard)"
RESET_ALREADY_APPLIED=0
if [[ "$BEST_TS" -eq "$prev" && "$BEST_MODE" == "$last_mode" \
      && "$BEST_MODE" != "standard" ]]; then
    RESET_ALREADY_APPLIED=1
fi

if [[ "$BEST_MODE" == "cold-start" && "$ACCEPT_COLD_START" -ne 1 \
      && "$RESET_ALREADY_APPLIED" -ne 1 ]]; then
    log_warn "发现全动态冷启动规则包；定时同步无权清空现有规则"
    log_warn "确认数据库基线已备份并准备好实时双路分流后，人工执行 --accept-cold-start"
    echo "$(date -u '+%FT%TZ') cold_start_waiting gen=$BEST_TS" >> "$SYNC_STATE_DIR/history.log"
    exit 0
fi
if [[ "$BEST_MODE" == "full-reset" && "$ACCEPT_FULL_RESET" -ne 1 \
      && "$RESET_ALREADY_APPLIED" -ne 1 ]]; then
    log_warn "发现全空 CIDR 重置包；定时同步无权清空全部 IP 分类依据"
    log_warn "确认本机递归优先逻辑已部署后，人工执行 --accept-full-reset"
    echo "$(date -u '+%FT%TZ') full_reset_waiting gen=$BEST_TS" >> "$SYNC_STATE_DIR/history.log"
    exit 0
fi
if [[ "$BEST_MODE" == "ip-reset" && "$ACCEPT_IP_RESET" -ne 1 \
      && "$RESET_ALREADY_APPLIED" -ne 1 ]]; then
    log_warn "发现 IP-only reset；定时同步无权清空 CN/污染 CIDR"
    log_warn "人工执行 --accept-ip-reset 后保留域名规则并清空全部 IP 规则"
    exit 0
fi
if [[ "$ACCEPT_COLD_START" -eq 1 && "$BEST_MODE" != "cold-start" ]]; then
    die "--accept-cold-start 只接受 bundle-mode=cold-start 的规则包"
fi
if [[ "$ACCEPT_FULL_RESET" -eq 1 && "$BEST_MODE" != "full-reset" ]]; then
    die "--accept-full-reset 只接受 bundle-mode=full-reset 的规则包"
fi
if [[ "$ACCEPT_IP_RESET" -eq 1 && "$BEST_MODE" != "ip-reset" ]]; then
    die "--accept-ip-reset 只接受 bundle-mode=ip-reset 的规则包"
fi

hold="$(cat "$SYNC_STATE_DIR/rollback-hold-generated-at" 2>/dev/null || echo 0)"
if [[ "$FORCE_DROP" -eq 0 && "$hold" -gt 0 && "$BEST_TS" -le "$hold" ]]; then
    log_warn "当前处于回滚保持状态，远端版本 $BEST_TS 未高于 $hold，本轮跳过"
    exit 0
fi
if [[ "$BEST_TS" -lt "$prev" ]]; then
    log_warn "下载版本 $BEST_TS 旧于本机 $prev，本轮跳过"
    echo "$(date -u '+%FT%TZ') stale_skipped remote=$BEST_TS local=$prev" \
        >> "$SYNC_STATE_DIR/history.log"
    exit 0
fi

cp -a "$BEST_DIR/clean/polluted-ip-cidr.txt" \
    "$BEST_DIR/polluted-ip-cidr.remote.txt"
if [[ "$BEST_MODE" == "standard" || "$RESET_ALREADY_APPLIED" -eq 1 ]]; then
    merge_polluted_cidrs "$BEST_DIR/polluted-ip-cidr.remote.txt" \
        "$BEST_DIR/clean/polluted-ip-cidr.txt"
else
    : > "$BEST_DIR/polluted-ip-cidr.remote.txt"
    : > "$BEST_DIR/clean/polluted-ip-cidr.txt"
fi
validate_cidr_disjoint "$BEST_DIR/clean/cn-ip-cidr.txt" \
    "$BEST_DIR/clean/polluted-ip-cidr.txt"

if [[ "$FORCE_DROP" -eq 0 && "$BEST_TS" -eq "$prev" && "$prev" -gt 0 \
      && -s "$REMOTE_POLLUTED_SNAPSHOT" ]] \
   && ! cmp -s "$BEST_DIR/polluted-ip-cidr.remote.txt" "$REMOTE_POLLUTED_SNAPSHOT"; then
    log_warn "远端污染快照与本机版本号相同($prev)但内容不同，拒绝覆盖"
    echo "$(date -u '+%FT%TZ') same_version_polluted_conflict gen=$prev" \
        >> "$SYNC_STATE_DIR/history.log"
    exit 0
fi

if [[ "$ACCEPT_IP_RESET" -eq 1 ]]; then
    log_warn "已人工确认 IP-only reset；保留域名规则并清空 CN/污染 CIDR 与本地污染集合"
elif [[ "$ACCEPT_FULL_RESET" -eq 1 ]]; then
    log_warn "已人工确认 full-reset；将清空全部域名/IP CIDR 与本地污染集合"
elif [[ "$ACCEPT_COLD_START" -eq 1 ]]; then
    log_warn "已人工确认全动态冷启动；将清空自动域名规则和本地累计污染集合"
elif [[ "$FORCE_DROP" -eq 1 ]]; then
    log_warn "已人工确认跳过条目数骤降/回滚保持保护；其余校验和失败回滚仍然生效"
else
    for f in "${FILES[@]}"; do
        old="$STATE_DIR/$f"; new="$BEST_DIR/clean/$f"
        if [[ -s "$old" ]]; then
            oc="$(grep -vcE '^[[:space:]]*(#|$)' "$old" || true)"; nc="$(wc -l < "$new")"
            if [[ "$oc" -gt 0 && "$nc" -eq 0 ]]; then
                log_warn "$f 从 $oc 条降为空集，保留旧规则待人工确认"
                exit 0
            elif [[ "$oc" -gt 20 && "$nc" -lt $((oc*80/100)) ]]; then
                log_warn "$f 从 $oc 骤降到 $nc，保留旧规则待人工确认"
                exit 0
            fi
        fi
    done
fi

if [[ "$RESET_ALREADY_APPLIED" -eq 1 ]]; then
    for f in cn.txt gfw.txt cn-ip-cidr.txt; do
        if ! cmp -s "$BEST_DIR/clean/$f" "$STATE_DIR/$f"; then
            die "已接受的 reset 版本只允许刷新本地污染集合，拒绝覆盖其它规则: $f"
        fi
    done
fi

all_same=1
for f in "${FILES[@]}"; do cmp -s "$BEST_DIR/clean/$f" "$STATE_DIR/$f" || all_same=0; done
[[ "$ACCEPT_COLD_START" -eq 1 || "$ACCEPT_FULL_RESET" -eq 1 \
   || "$ACCEPT_IP_RESET" -eq 1 ]] && all_same=0
if [[ "$all_same" -eq 1 ]]; then
    install -m 0644 "$BEST_DIR/polluted-ip-cidr.remote.txt" \
        "$SYNC_STATE_DIR/.polluted-ip-cidr.remote.txt.new"
    mv -f "$SYNC_STATE_DIR/.polluted-ip-cidr.remote.txt.new" \
        "$REMOTE_POLLUTED_SNAPSHOT"
    echo "$BEST_TS" > "$SYNC_STATE_DIR/last-generated-at"
    echo "$BEST_MODE" > "$SYNC_STATE_DIR/last-bundle-mode"
    rm -f "$SYNC_STATE_DIR/rollback-hold-generated-at"
    log_ok "内容无变化，不重载"
    exit 0
fi
if [[ "$FORCE_DROP" -eq 0 && "$RESET_ALREADY_APPLIED" -ne 1 \
      && "$BEST_TS" -eq "$prev" && "$prev" -gt 0 ]]; then
    log_warn "远端规则与本机版本号相同($prev)但内容不同，拒绝覆盖"
    echo "$(date -u '+%FT%TZ') same_version_conflict gen=$prev" \
        >> "$SYNC_STATE_DIR/history.log"
    exit 0
fi

BACKUP="$(mktemp -d "$HISTORY_DIR/.attempt-$(date '+%Y%m%d%H%M%S')-XXXXXX")"
backup_current "$BACKUP"
APPLIED=0
rollback_on_error() {
    local rc=$?
    trap - ERR
    if [[ "$APPLIED" -eq 1 ]]; then
        log_err "替换过程中发生错误，恢复完整旧规则包"
        restore_bundle "$BACKUP" || log_err "回滚后 mosproxy reload 失败，请立即检查服务"
    fi
    rm -f "$STATE_DIR"/.*.txt.new "$SYNC_STATE_DIR"/.*.txt.new 2>/dev/null || true
    rm -rf "$BACKUP"
    exit "$rc"
}
trap rollback_on_error ERR
for f in "${FILES[@]}"; do
    install -m 0644 "$BEST_DIR/clean/$f" "$STATE_DIR/.${f}.new"
done
install -m 0644 "$BEST_DIR/polluted-ip-cidr.remote.txt" \
    "$SYNC_STATE_DIR/.polluted-ip-cidr.remote.txt.new"
if [[ "$ACCEPT_COLD_START" -eq 1 || "$ACCEPT_FULL_RESET" -eq 1 \
      || "$ACCEPT_IP_RESET" -eq 1 ]]; then
    : > "$SYNC_STATE_DIR/.polluted-ip-cidr.local.txt.new"
    : > "$STATE_DIR/.polluted-ip.txt.new"
    chmod 0644 "$SYNC_STATE_DIR/.polluted-ip-cidr.local.txt.new" \
        "$STATE_DIR/.polluted-ip.txt.new"
fi
APPLIED=1
for f in "${FILES[@]}"; do mv -f "$STATE_DIR/.${f}.new" "$STATE_DIR/$f"; done
mv -f "$SYNC_STATE_DIR/.polluted-ip-cidr.remote.txt.new" \
    "$REMOTE_POLLUTED_SNAPSHOT"
if [[ "$ACCEPT_COLD_START" -eq 1 || "$ACCEPT_FULL_RESET" -eq 1 \
      || "$ACCEPT_IP_RESET" -eq 1 ]]; then
    mv -f "$SYNC_STATE_DIR/.polluted-ip-cidr.local.txt.new" "$LOCAL_POLLUTED_CIDRS"
    mv -f "$STATE_DIR/.polluted-ip.txt.new" "$LOCAL_POLLUTED_IPS"
fi

code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://${MOSPROXY_API}/ctl/reload" || echo 000)"
if [[ "$code" != 200 ]] || ! dig @127.0.0.1 -p 5335 example.com A +time=3 +tries=1 +short >/dev/null 2>&1; then
    restore_bundle "$BACKUP" || log_err "回滚后 mosproxy reload 失败，请立即检查服务"
    rm -rf "$BACKUP"
    die "重载或健康检查失败，已回滚完整规则包"
fi
APPLIED=0
trap - ERR

HISTORY_BACKUP="$HISTORY_DIR/bundle-${BACKUP##*/.attempt-}"
if [[ "$RULE_BUNDLE_HISTORY_KEEP" -gt 0 ]]; then
    mv "$BACKUP" "$HISTORY_BACKUP"
else
    rm -rf "$BACKUP"
fi

echo "$BEST_TS" > "$SYNC_STATE_DIR/last-generated-at"
echo "$BEST_MODE" > "$SYNC_STATE_DIR/last-bundle-mode"
rm -f "$SYNC_STATE_DIR/rollback-hold-generated-at"
if [[ "$RULE_BUNDLE_HISTORY_KEEP" -gt 0 ]]; then
    find "$HISTORY_DIR" -maxdepth 1 -type d -name 'bundle-*' -printf '%T@ %p\n' 2>/dev/null \
      | sort -nr | tail -n "+$((RULE_BUNDLE_HISTORY_KEEP + 1))" \
      | cut -d' ' -f2- | xargs -r rm -rf
fi
echo "$(date -u '+%FT%TZ') bundle_ok gen=$BEST_TS mode=$BEST_MODE" >> "$SYNC_STATE_DIR/history.log"
log_ok "四个规则文件已原子同步并重载"
