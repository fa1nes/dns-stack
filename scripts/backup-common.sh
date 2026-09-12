#!/usr/bin/env bash

set -o pipefail

: "${CONFIG_FILE:=/etc/dns-stack/config.env}"
: "${SECRETS_DIR:=/etc/dns-stack/secrets}"
: "${STATE_DIR:=/var/lib/dns-stack}"
: "${LOG_DIR:=/var/log/dns-stack}"
: "${BACKUP_DIR:=/var/backups/dns-stack}"
: "${EXPORT_DIR:=/srv/dns-stack/export}"
: "${SYSTEMD_DIR:=/etc/systemd/system}"

bc_role() {
    [[ -f "$CONFIG_FILE" ]] && grep -E '^ROLE=' "$CONFIG_FILE" | head -1 | cut -d= -f2- || echo "unknown"
}

bc_config_int() {
    local key="$1" default="$2" min="$3" max="$4" value=""
    if [[ -f "$CONFIG_FILE" ]]; then
        value=$(grep -E "^${key}=[0-9]+$" "$CONFIG_FILE" | tail -1 | cut -d= -f2- || true)
    fi
    if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value < min || value > max )); then
        value="$default"
    fi
    printf '%s\n' "$value"
}

bc_check_disk_space() {
    local avail_kb
    avail_kb=$(df -Pk "$BACKUP_DIR" | tail -1 | awk '{print $4}')
    if [[ "${avail_kb:-0}" -lt 512000 ]]; then
        log_err "磁盘空间不足(可用 $((avail_kb/1024))MB)，取消操作"
        return 1
    fi
    return 0
}

bc_sqlite_backup() {
    local src="$1" dst="$2"
    if [[ -f "$src" ]]; then
        sqlite3 "$src" ".backup '${dst}'"
    fi
}

bc_collect_payload() {
    local mode="$1"       # config | state | full
    local include_secrets="$2"  # 0/1
    local include_logs="$3"     # 0/1
    local dest="$4"
    local role
    role="$(bc_role)"

    mkdir -p "$dest"/{config,state,versions,systemd}

    [[ -f "$CONFIG_FILE" ]] && cp -a "$CONFIG_FILE" "$dest/config/"
    [[ -d /etc/unbound/unbound.conf.d ]] && cp -a /etc/unbound/unbound.conf.d "$dest/config/unbound.conf.d"
    for mpdir in "$(dirname "$CONFIG_FILE")/mosproxy" /etc/mosproxy; do
        if [[ -d "$mpdir" ]]; then
            mkdir -p "$dest/config/mosproxy"
            find "$mpdir" -maxdepth 1 -type f ! -name '*.bak*' -exec cp -a {} "$dest/config/mosproxy/" \; 2>/dev/null || true
            break
        fi
    done

    [[ -f /opt/dns-stack/versions.lock ]] && cp -a /opt/dns-stack/versions.lock "$dest/versions/"

    for unit in dns-stack-helper dns-stack-panel dns-stack-classify dns-stack-verify dns-stack-backup \
                dns-stack-sync-rules dns-stack-renew-cert dns-stack-collect-polluted dns-stack-reference-data \
                dns-stack-publish \
                dns-stack-recursive-routing dns-stack-chnroute dns-stack-cn-authority \
                unbound mosproxy; do
        [[ -f "$SYSTEMD_DIR/${unit}.service" ]] && cp -a "$SYSTEMD_DIR/${unit}.service" "$dest/systemd/"
        [[ -f "$SYSTEMD_DIR/${unit}.timer" ]] && cp -a "$SYSTEMD_DIR/${unit}.timer" "$dest/systemd/"
    done

    if [[ "$mode" == "state" || "$mode" == "full" ]]; then
        if [[ "$role" == "cn-resolver" ]]; then
            mkdir -p "$dest/state/rule-history" "$dest/state/sync-state"
            bc_sqlite_backup "$STATE_DIR/collector.db" "$dest/state/collector.db"
            cp -a "$STATE_DIR/rule-history/." "$dest/state/rule-history/" 2>/dev/null || true
            cp -a "$STATE_DIR/sync-state/." "$dest/state/sync-state/" 2>/dev/null || true

            local go_bin="${DNS_STACK_GO_BIN:-/opt/dns-stack/bin/dns-stack-go}"
            if [[ -x "$go_bin" ]]; then
                mkdir -p "$dest/state"
                "$go_bin" migration-export --out "$dest/state/migration.tar.gz" \
                    --state "$STATE_DIR" 2>/dev/null \
                    || echo "  ! 迁移包导出失败，本次备份缺少规则与 chnroute 状态" >&2
            else
                echo "  ! 缺少 $go_bin，本次备份缺少规则与 chnroute 状态" >&2
            fi
        else
            mkdir -p "$dest/state/git-state"
            bc_sqlite_backup "$STATE_DIR/classifier.db" "$dest/state/classifier.db"
            for f in manual-cn.txt manual-gfw.txt manual-exclude.txt; do
                [[ -f "$STATE_DIR/$f" ]] && cp -a "$STATE_DIR/$f" "$dest/state/"
            done
            [[ -d "$STATE_DIR/publish" ]] && cp -a "$STATE_DIR/publish" "$dest/state/publish"
        fi
    fi

    if [[ "$include_logs" -eq 1 ]]; then
        mkdir -p "$dest/logs"
        cp -a "$LOG_DIR"/*.log "$dest/logs/" 2>/dev/null || true
    fi

    if [[ "$include_secrets" -eq 1 ]]; then
        mkdir -p "$dest/secrets"
        cp -a "$SECRETS_DIR"/. "$dest/secrets/" 2>/dev/null || true
    fi
}

bc_write_manifest() {
    local dest="$1" mode="$2" include_secrets="$3" include_logs="$4"
    local role arch hostname_v now
    role="$(bc_role)"
    arch="$(uname -m)"
    hostname_v="$(hostname)"
    now="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    cat > "$dest/manifest.json" << EOF
{
  "role": "${role}",
  "arch": "${arch}",
  "hostname": "${hostname_v}",
  "created_at": "${now}",
  "mode": "${mode}",
  "include_secrets": $([[ "$include_secrets" -eq 1 ]] && echo true || echo false),
  "include_logs": $([[ "$include_logs" -eq 1 ]] && echo true || echo false),
  "schema_version": 1
}
EOF
}

bc_write_checksums() {
    local dest="$1"
    ( cd "$dest" && find . -type f ! -name checksums.sha256 -print0 | sort -z | xargs -0 sha256sum > checksums.sha256 )
}

bc_verify_checksums() {
    local dest="$1"
    ( cd "$dest" && sha256sum -c checksums.sha256 --quiet )
}

bc_pack() {
    local src_dir="$1" out_file_noext="$2" encrypt="$3"
    local tar_zst="${out_file_noext}.tar.zst"
    local level threads
    level="${BACKUP_ZSTD_LEVEL:-6}"
    threads="${BACKUP_ZSTD_THREADS:-2}"
    tar -C "$(dirname "$src_dir")" -c "$(basename "$src_dir")" |
        zstd -q "-${level}" "-T${threads}" -o "$tar_zst"
    if [[ "$encrypt" -eq 1 ]]; then
        local age_recipient_file="$SECRETS_DIR/backup-age-recipient.txt"
        local age_identity_file="$SECRETS_DIR/backup-age-identity.txt"
        if [[ ! -f "$age_identity_file" ]]; then
            mkdir -p "$SECRETS_DIR"
            age-keygen -o "$age_identity_file" 2>/dev/null
            chmod 0600 "$age_identity_file"
            grep '^# public key:' "$age_identity_file" | sed 's/# public key: //' > "$age_recipient_file"
        fi
        age -r "$(cat "$age_recipient_file")" -o "${tar_zst}.age" "$tar_zst"
        rm -f "$tar_zst"
        echo "${tar_zst}.age"
    else
        echo "$tar_zst"
    fi
}

bc_cleanup_old_backups() {
    local daily_keep="${1:-14}" weekly_keep="${2:-8}"
    local files
    mapfile -t files < <(find "$BACKUP_DIR" -maxdepth 1 -name 'daily-*.tar.zst*' -printf '%T@ %p\n' 2>/dev/null | sort -rn | awk '{print $2}')
    if [[ "${#files[@]}" -gt "$daily_keep" ]]; then
        for ((i=daily_keep; i<${#files[@]}; i++)); do
            rm -f -- "${files[$i]}"
        done
    fi
    mapfile -t files < <(find "$BACKUP_DIR" -maxdepth 1 -name 'weekly-*.tar.zst*' -printf '%T@ %p\n' 2>/dev/null | sort -rn | awk '{print $2}')
    if [[ "${#files[@]}" -gt "$weekly_keep" ]]; then
        for ((i=weekly_keep; i<${#files[@]}; i++)); do
            rm -f -- "${files[$i]}"
        done
    fi
}
