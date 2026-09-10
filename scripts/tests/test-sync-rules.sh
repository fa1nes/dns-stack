#!/usr/bin/env bash
set -Eeuo pipefail
export RULE_BUNDLE_HISTORY_KEEP=5

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
STATE_DIR="$WORK/state"
CONFIG_FILE="$WORK/config.env"
BIN="$WORK/bin"
mkdir -p "$STATE_DIR" "$BIN" "$WORK/remote-v1" "$WORK/remote-v2" \
         "$WORK/remote-v3" "$WORK/remote-stale" "$WORK/remote-drop" \
         "$WORK/remote-merge" "$WORK/remote-cold" "$WORK/remote-full-reset"
mkdir -p "$WORK/remote-ip-reset" "$WORK/remote-overlap" \
         "$WORK/remote-empty-gfw" "$WORK/remote-empty-all" "$WORK/remote-order"

write_bundle() {
    local dir="$1" ts="$2" cn="$3" gfw="$4"
    printf '# generated-at: %s\n# bundle-mode: standard\n%s\n' "$ts" "$cn" > "$dir/cn.txt"
    printf '# generated-at: %s\n# bundle-mode: standard\n%s\n' "$ts" "$gfw" > "$dir/gfw.txt"
    printf '# generated-at: %s\n# bundle-mode: standard\n1.2.0.0/16\n2001:db8::/32\n' "$ts" > "$dir/cn-ip-cidr.txt"
    printf '# generated-at: %s\n# bundle-mode: standard\n8.8.8.8/32\n2001::1/128\n' "$ts" > "$dir/polluted-ip-cidr.txt"
}

write_cold_bundle() {
    local dir="$1" ts="$2" f
    for f in cn.txt gfw.txt cn-ip-cidr.txt polluted-ip-cidr.txt; do
        printf '# generated-at: %s\n# bundle-mode: cold-start\n' "$ts" > "$dir/$f"
    done
}

write_empty_standard_bundle() {
    local dir="$1" ts="$2" f
    for f in cn.txt gfw.txt cn-ip-cidr.txt polluted-ip-cidr.txt; do
        printf '# generated-at: %s\n# bundle-mode: standard\n' "$ts" > "$dir/$f"
    done
}

write_full_reset_bundle() {
    local dir="$1" ts="$2" f
    for f in cn.txt gfw.txt cn-ip-cidr.txt polluted-ip-cidr.txt; do
        printf '# generated-at: %s\n# bundle-mode: full-reset\n' "$ts" > "$dir/$f"
    done
}

write_ip_reset_bundle() {
    local dir="$1" ts="$2"
    printf '# generated-at: %s\n# bundle-mode: ip-reset\nkept-cn.example\n' "$ts" > "$dir/cn.txt"
    printf '# generated-at: %s\n# bundle-mode: ip-reset\nkept-gfw.example\n' "$ts" > "$dir/gfw.txt"
    printf '# generated-at: %s\n# bundle-mode: ip-reset\n' "$ts" > "$dir/cn-ip-cidr.txt"
    printf '# generated-at: %s\n# bundle-mode: ip-reset\n' "$ts" > "$dir/polluted-ip-cidr.txt"
}

write_bundle "$WORK/remote-v1" 100 new-cn.example new-gfw.example
write_bundle "$WORK/remote-v2" 200 broken-cn.example broken-gfw.example
write_bundle "$WORK/remote-v3" 300 newest-cn.example newest-gfw.example
write_bundle "$WORK/remote-stale" 50 stale-cn.example stale-gfw.example
write_bundle "$WORK/remote-merge" 700 merged-cn.example merged-gfw.example
write_bundle "$WORK/remote-overlap" 710 overlap-cn.example overlap-gfw.example
write_bundle "$WORK/remote-empty-gfw" 720 empty-gfw-cn.example ""
write_empty_standard_bundle "$WORK/remote-empty-all" 725
write_bundle "$WORK/remote-order" 730 $'tanhuatv.site\nt.me' order-gfw.example
printf '# generated-at: 710\n# bundle-mode: standard\n1.2.3.4/32\n' \
    > "$WORK/remote-overlap/polluted-ip-cidr.txt"
write_full_reset_bundle "$WORK/remote-full-reset" 900
write_cold_bundle "$WORK/remote-cold" 800
write_ip_reset_bundle "$WORK/remote-ip-reset" 950
printf 'old-cn.example\n' > "$STATE_DIR/cn.txt"
printf 'old-gfw.example\n' > "$STATE_DIR/gfw.txt"
printf '10.0.0.0/8\n' > "$STATE_DIR/cn-ip-cidr.txt"
printf '9.9.9.9/32\n' > "$STATE_DIR/polluted-ip-cidr.txt"

cat > "$BIN/curl" <<'EOF'
#!/usr/bin/env bash
set -e
out=""; url=""; want_code=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        -w) want_code=1; shift 2 ;;
        -*) shift ;;
        *) url="$1"; shift ;;
    esac
done
if [[ "$url" == http://*/ctl/reload ]]; then
    if [[ "${FAIL_RELOAD:-0}" == 1 ]]; then
        if [[ "$want_code" == 1 ]]; then printf 500; exit 0; fi
        exit 22
    fi
    [[ "$want_code" == 1 ]] && printf 200
    exit 0
fi
src="${url#file://}"
cp "$src" "$out"
EOF
cat > "$BIN/dig" <<'EOF'
#!/usr/bin/env bash
echo 93.184.216.34
EOF
cat > "$BIN/python3" <<'EOF'
#!/usr/bin/env bash
exec "${TEST_PYTHON:-/usr/bin/python3}" "$@"
EOF
chmod +x "$BIN/curl" "$BIN/dig" "$BIN/python3"

export CONFIG_FILE STATE_DIR PATH="$BIN:$PATH"
printf 'GITHUB_RAW_BASE=file://%s\n' "$WORK/remote-v1" > "$CONFIG_FILE"
bash "$ROOT/scripts/sync-rules.sh"
grep -qx 'new-cn.example' "$STATE_DIR/cn.txt"
grep -qx 'new-gfw.example' "$STATE_DIR/gfw.txt"

ORDER_STATE="$WORK/order-state"
mkdir -p "$ORDER_STATE"
printf 'GITHUB_RAW_BASE=file://%s\n' "$WORK/remote-order" > "$CONFIG_FILE"
export STATE_DIR="$ORDER_STATE"
bash "$ROOT/scripts/sync-rules.sh"
printf 't.me\ntanhuatv.site\n' | cmp - "$ORDER_STATE/cn.txt"
export STATE_DIR="$WORK/state"
echo "SYNC_RULES_DOMAIN_ORDER_OK"

printf 'GITHUB_RAW_BASE=file://%s\nGITHUB_MIRROR_1=file://%s\n' \
    "$WORK/remote-v1" "$WORK/remote-v3" > "$CONFIG_FILE"
bash "$ROOT/scripts/sync-rules.sh"
grep -qx 'newest-cn.example' "$STATE_DIR/cn.txt"
grep -qx '300' "$STATE_DIR/sync-state/last-generated-at"

printf 'GITHUB_RAW_BASE=file://%s\n' "$WORK/remote-stale" > "$CONFIG_FILE"
bash "$ROOT/scripts/sync-rules.sh"
grep -qx 'newest-cn.example' "$STATE_DIR/cn.txt"
write_bundle "$WORK/remote-v3" 300 tampered-cn.example tampered-gfw.example
printf 'GITHUB_RAW_BASE=file://%s\n' "$WORK/remote-v3" > "$CONFIG_FILE"
bash "$ROOT/scripts/sync-rules.sh"
grep -qx 'newest-cn.example' "$STATE_DIR/cn.txt"

write_bundle "$WORK/remote-v1" 400 new-cn.example new-gfw.example
printf 'GITHUB_RAW_BASE=file://%s\n' "$WORK/remote-v1" > "$CONFIG_FILE"
bash "$ROOT/scripts/sync-rules.sh"

export FAIL_RELOAD=1
if bash "$ROOT/scripts/sync-rules.sh" --rollback; then
    echo "预期人工回滚 reload 失败，但脚本返回成功" >&2
    exit 1
fi
grep -qx 'new-cn.example' "$STATE_DIR/cn.txt"
unset FAIL_RELOAD
bash "$ROOT/scripts/sync-rules.sh" --rollback
grep -qx 'newest-cn.example' "$STATE_DIR/cn.txt"
grep -qx '300' "$STATE_DIR/sync-state/last-generated-at"
grep -qx '400' "$STATE_DIR/sync-state/rollback-hold-generated-at"
bash "$ROOT/scripts/sync-rules.sh"
grep -qx 'newest-cn.example' "$STATE_DIR/cn.txt"

bash "$ROOT/scripts/sync-rules.sh" --force
grep -qx 'new-cn.example' "$STATE_DIR/cn.txt"
grep -qx '400' "$STATE_DIR/sync-state/last-generated-at"
[[ ! -e "$STATE_DIR/sync-state/rollback-hold-generated-at" ]]

bash "$ROOT/scripts/sync-rules.sh" --rollback
grep -qx 'newest-cn.example' "$STATE_DIR/cn.txt"
grep -qx '300' "$STATE_DIR/sync-state/last-generated-at"

write_bundle "$WORK/remote-v2" 500 broken-cn.example broken-gfw.example
printf 'GITHUB_RAW_BASE=file://%s\n' "$WORK/remote-v2" > "$CONFIG_FILE"
export FAIL_RELOAD=1
HISTORY_BEFORE="$(find "$STATE_DIR/rule-history" -maxdepth 1 -type d -name 'bundle-[0-9]*' | wc -l)"
if bash "$ROOT/scripts/sync-rules.sh"; then
    echo "预期 reload 失败，但同步脚本返回成功" >&2
    exit 1
fi
HISTORY_AFTER="$(find "$STATE_DIR/rule-history" -maxdepth 1 -type d -name 'bundle-[0-9]*' | wc -l)"
[[ "$HISTORY_BEFORE" -eq "$HISTORY_AFTER" ]]
grep -qx 'newest-cn.example' "$STATE_DIR/cn.txt"
grep -qx 'newest-gfw.example' "$STATE_DIR/gfw.txt"
grep -qx '1.2.0.0/16' "$STATE_DIR/cn-ip-cidr.txt"
grep -qx '8.8.8.8/32' "$STATE_DIR/polluted-ip-cidr.txt"
echo "SYNC_RULES_ROLLBACK_OK"

FRESH_STATE="$WORK/fresh-state"
mkdir -p "$FRESH_STATE"
export STATE_DIR="$FRESH_STATE"
if bash "$ROOT/scripts/sync-rules.sh"; then
    echo "预期首次同步 reload 失败，但脚本返回成功" >&2
    exit 1
fi
for f in cn.txt gfw.txt cn-ip-cidr.txt polluted-ip-cidr.txt; do
    [[ ! -e "$FRESH_STATE/$f" ]]
done
echo "SYNC_RULES_FIRST_INSTALL_ROLLBACK_OK"

unset FAIL_RELOAD
DROP_STATE="$WORK/drop-state"
mkdir -p "$DROP_STATE"
for i in $(seq 1 25); do printf 'old-%02d.example\n' "$i"; done > "$DROP_STATE/cn.txt"
printf 'old-gfw.example\n' > "$DROP_STATE/gfw.txt"
printf '10.0.0.0/8\n' > "$DROP_STATE/cn-ip-cidr.txt"
printf '9.9.9.9/32\n' > "$DROP_STATE/polluted-ip-cidr.txt"
write_bundle "$WORK/remote-drop" 600 compact-cn.example compact-gfw.example
printf 'GITHUB_RAW_BASE=file://%s\n' "$WORK/remote-drop" > "$CONFIG_FILE"
export STATE_DIR="$DROP_STATE"
bash "$ROOT/scripts/sync-rules.sh"
grep -qx 'old-01.example' "$DROP_STATE/cn.txt"
bash "$ROOT/scripts/sync-rules.sh" --force
grep -qx 'compact-cn.example' "$DROP_STATE/cn.txt"
echo "SYNC_RULES_FORCE_DROP_OK"

EMPTY_GFW_STATE="$WORK/empty-gfw-state"
mkdir -p "$EMPTY_GFW_STATE"
printf 'old-cn.example\n' > "$EMPTY_GFW_STATE/cn.txt"
printf 'old-gfw.example\n' > "$EMPTY_GFW_STATE/gfw.txt"
printf '10.0.0.0/8\n' > "$EMPTY_GFW_STATE/cn-ip-cidr.txt"
printf '9.9.9.9/32\n' > "$EMPTY_GFW_STATE/polluted-ip-cidr.txt"
printf 'GITHUB_RAW_BASE=file://%s\n' "$WORK/remote-empty-gfw" > "$CONFIG_FILE"
export STATE_DIR="$EMPTY_GFW_STATE"
bash "$ROOT/scripts/sync-rules.sh"
grep -qx 'old-gfw.example' "$EMPTY_GFW_STATE/gfw.txt"
bash "$ROOT/scripts/sync-rules.sh" --force
grep -qx 'empty-gfw-cn.example' "$EMPTY_GFW_STATE/cn.txt"
[[ -f "$EMPTY_GFW_STATE/gfw.txt" && ! -s "$EMPTY_GFW_STATE/gfw.txt" ]]
echo "SYNC_RULES_EMPTY_GFW_CONFIRMATION_OK"

EMPTY_ALL_STATE="$WORK/empty-all-state"
mkdir -p "$EMPTY_ALL_STATE"
printf 'GITHUB_RAW_BASE=file://%s\n' "$WORK/remote-empty-all" > "$CONFIG_FILE"
export STATE_DIR="$EMPTY_ALL_STATE"
bash "$ROOT/scripts/sync-rules.sh"
for f in cn.txt gfw.txt cn-ip-cidr.txt polluted-ip-cidr.txt; do
    [[ -f "$EMPTY_ALL_STATE/$f" && ! -s "$EMPTY_ALL_STATE/$f" ]]
done
grep -qx '725' "$EMPTY_ALL_STATE/sync-state/last-generated-at"
echo "SYNC_RULES_EMPTY_STANDARD_OK"

MERGE_STATE="$WORK/merge-state"
mkdir -p "$MERGE_STATE/sync-state"
printf 'old-cn.example\n' > "$MERGE_STATE/cn.txt"
printf 'old-gfw.example\n' > "$MERGE_STATE/gfw.txt"
printf '10.0.0.0/8\n' > "$MERGE_STATE/cn-ip-cidr.txt"
: > "$MERGE_STATE/polluted-ip.txt"
: > "$MERGE_STATE/polluted-ip-cidr.txt"
for i in $(seq 1 25); do
    printf '198.51.100.%d\n' "$((i * 2 - 1))" >> "$MERGE_STATE/polluted-ip.txt"
    printf '198.51.100.%d/32\n' "$((i * 2 - 1))" >> "$MERGE_STATE/polluted-ip-cidr.txt"
done
printf '650\n' > "$MERGE_STATE/sync-state/last-generated-at"
printf 'GITHUB_RAW_BASE=file://%s\n' "$WORK/remote-merge" > "$CONFIG_FILE"
export STATE_DIR="$MERGE_STATE"
bash "$ROOT/scripts/sync-rules.sh"
grep -qx 'merged-cn.example' "$MERGE_STATE/cn.txt"
grep -qx '700' "$MERGE_STATE/sync-state/last-generated-at"
grep -qx '8.8.8.8/32' "$MERGE_STATE/polluted-ip-cidr.txt"
grep -qx '198.51.100.1/32' "$MERGE_STATE/polluted-ip-cidr.txt"
grep -qx '8.8.8.8/32' "$MERGE_STATE/sync-state/polluted-ip-cidr.remote.txt"
! grep -q '198.51.100.1' "$MERGE_STATE/sync-state/polluted-ip-cidr.remote.txt"
echo "SYNC_RULES_LOCAL_POLLUTION_MERGE_OK"

OVERLAP_STATE="$WORK/overlap-state"
mkdir -p "$OVERLAP_STATE"
printf 'kept-cn.example\n' > "$OVERLAP_STATE/cn.txt"
printf 'kept-gfw.example\n' > "$OVERLAP_STATE/gfw.txt"
printf '10.0.0.0/8\n' > "$OVERLAP_STATE/cn-ip-cidr.txt"
printf '9.9.9.9/32\n' > "$OVERLAP_STATE/polluted-ip-cidr.txt"
printf '700\n' > "$OVERLAP_STATE/sync-state-generation"
printf 'GITHUB_RAW_BASE=file://%s\n' "$WORK/remote-overlap" > "$CONFIG_FILE"
export STATE_DIR="$OVERLAP_STATE"
bash "$ROOT/scripts/sync-rules.sh"
grep -qx 'kept-cn.example' "$OVERLAP_STATE/cn.txt"
grep -qx '10.0.0.0/8' "$OVERLAP_STATE/cn-ip-cidr.txt"
echo "SYNC_RULES_REMOTE_CIDR_OVERLAP_REJECTED"

LOCAL_OVERLAP_STATE="$WORK/local-overlap-state"
mkdir -p "$LOCAL_OVERLAP_STATE/sync-state"
printf 'kept-cn.example\n' > "$LOCAL_OVERLAP_STATE/cn.txt"
printf 'kept-gfw.example\n' > "$LOCAL_OVERLAP_STATE/gfw.txt"
printf '10.0.0.0/8\n' > "$LOCAL_OVERLAP_STATE/cn-ip-cidr.txt"
printf '9.9.9.9/32\n' > "$LOCAL_OVERLAP_STATE/polluted-ip-cidr.txt"
printf '1.2.3.4/32\n' > \
    "$LOCAL_OVERLAP_STATE/sync-state/polluted-ip-cidr.local.txt"
printf 'GITHUB_RAW_BASE=file://%s\n' "$WORK/remote-merge" > "$CONFIG_FILE"
export STATE_DIR="$LOCAL_OVERLAP_STATE"
if bash "$ROOT/scripts/sync-rules.sh"; then
    echo "预期本地污染 CIDR 与下载 CN CIDR 冲突，但同步脚本返回成功" >&2
    exit 1
fi
grep -qx 'kept-cn.example' "$LOCAL_OVERLAP_STATE/cn.txt"
grep -qx '10.0.0.0/8' "$LOCAL_OVERLAP_STATE/cn-ip-cidr.txt"
echo "SYNC_RULES_LOCAL_CIDR_OVERLAP_REJECTED"

COLD_STATE="$WORK/cold-state"
mkdir -p "$COLD_STATE/sync-state"
printf 'kept-cn.example\n' > "$COLD_STATE/cn.txt"
printf 'kept-gfw.example\n' > "$COLD_STATE/gfw.txt"
printf '10.0.0.0/8\n' > "$COLD_STATE/cn-ip-cidr.txt"
printf '9.9.9.9/32\n' > "$COLD_STATE/polluted-ip-cidr.txt"
printf '9.9.9.9\n' > "$COLD_STATE/polluted-ip.txt"
printf '9.9.9.9/32\n' > "$COLD_STATE/sync-state/polluted-ip-cidr.local.txt"
printf '750\n' > "$COLD_STATE/sync-state/last-generated-at"
printf 'GITHUB_RAW_BASE=file://%s\n' "$WORK/remote-cold" > "$CONFIG_FILE"
export STATE_DIR="$COLD_STATE"
bash "$ROOT/scripts/sync-rules.sh"
grep -qx 'kept-cn.example' "$COLD_STATE/cn.txt"
bash "$ROOT/scripts/sync-rules.sh" --accept-cold-start
[[ ! -s "$COLD_STATE/cn.txt" ]]
[[ ! -s "$COLD_STATE/gfw.txt" ]]
[[ ! -s "$COLD_STATE/polluted-ip-cidr.txt" ]]
[[ ! -s "$COLD_STATE/polluted-ip.txt" ]]
[[ ! -s "$COLD_STATE/sync-state/polluted-ip-cidr.local.txt" ]]
[[ ! -s "$COLD_STATE/cn-ip-cidr.txt" ]]
grep -qx '800' "$COLD_STATE/sync-state/last-generated-at"
bash "$ROOT/scripts/sync-rules.sh" --rollback
grep -qx 'kept-cn.example' "$COLD_STATE/cn.txt"
grep -qx '9.9.9.9' "$COLD_STATE/polluted-ip.txt"
grep -qx '9.9.9.9/32' "$COLD_STATE/sync-state/polluted-ip-cidr.local.txt"
echo "SYNC_RULES_COLD_START_OK"

FULL_STATE="$WORK/full-reset-state"
mkdir -p "$FULL_STATE/sync-state"
printf 'kept-cn.example\n' > "$FULL_STATE/cn.txt"
printf 'kept-gfw.example\n' > "$FULL_STATE/gfw.txt"
printf '10.0.0.0/8\n' > "$FULL_STATE/cn-ip-cidr.txt"
printf '9.9.9.9/32\n' > "$FULL_STATE/polluted-ip-cidr.txt"
printf '9.9.9.9\n' > "$FULL_STATE/polluted-ip.txt"
printf '9.9.9.9/32\n' > "$FULL_STATE/sync-state/polluted-ip-cidr.local.txt"
printf '850\n' > "$FULL_STATE/sync-state/last-generated-at"
printf 'GITHUB_RAW_BASE=file://%s\n' "$WORK/remote-full-reset" > "$CONFIG_FILE"
export STATE_DIR="$FULL_STATE"
bash "$ROOT/scripts/sync-rules.sh"
grep -qx '10.0.0.0/8' "$FULL_STATE/cn-ip-cidr.txt"
bash "$ROOT/scripts/sync-rules.sh" --accept-full-reset
for f in cn.txt gfw.txt cn-ip-cidr.txt polluted-ip-cidr.txt polluted-ip.txt; do
    [[ ! -s "$FULL_STATE/$f" ]]
done
[[ ! -s "$FULL_STATE/sync-state/polluted-ip-cidr.local.txt" ]]
grep -qx '900' "$FULL_STATE/sync-state/last-generated-at"
echo "SYNC_RULES_FULL_RESET_OK"

IP_RESET_STATE="$WORK/ip-reset-state"
mkdir -p "$IP_RESET_STATE/sync-state"
printf 'old-cn.example\n' > "$IP_RESET_STATE/cn.txt"
printf 'old-gfw.example\n' > "$IP_RESET_STATE/gfw.txt"
printf '10.0.0.0/8\n' > "$IP_RESET_STATE/cn-ip-cidr.txt"
printf '9.9.9.9/32\n' > "$IP_RESET_STATE/polluted-ip-cidr.txt"
printf '9.9.9.9\n' > "$IP_RESET_STATE/polluted-ip.txt"
printf 'GITHUB_RAW_BASE=file://%s\n' "$WORK/remote-ip-reset" > "$CONFIG_FILE"
export STATE_DIR="$IP_RESET_STATE"
bash "$ROOT/scripts/sync-rules.sh"
grep -qx '10.0.0.0/8' "$IP_RESET_STATE/cn-ip-cidr.txt"
bash "$ROOT/scripts/sync-rules.sh" --accept-ip-reset
grep -qx 'kept-cn.example' "$IP_RESET_STATE/cn.txt"
grep -qx 'kept-gfw.example' "$IP_RESET_STATE/gfw.txt"
[[ ! -s "$IP_RESET_STATE/cn-ip-cidr.txt" ]]
[[ ! -s "$IP_RESET_STATE/polluted-ip-cidr.txt" ]]
[[ ! -s "$IP_RESET_STATE/polluted-ip.txt" ]]
echo "SYNC_RULES_IP_RESET_OK"

printf '6.6.6.6\n' > "$IP_RESET_STATE/polluted-ip.txt"
printf '6.6.6.6/32\n' > "$IP_RESET_STATE/sync-state/polluted-ip-cidr.local.txt"
bash "$ROOT/scripts/sync-rules.sh"
grep -qx 'kept-cn.example' "$IP_RESET_STATE/cn.txt"
grep -qx 'kept-gfw.example' "$IP_RESET_STATE/gfw.txt"
[[ ! -s "$IP_RESET_STATE/cn-ip-cidr.txt" ]]
grep -qx '6.6.6.6/32' "$IP_RESET_STATE/polluted-ip-cidr.txt"
echo "SYNC_RULES_ACCEPTED_RESET_LOCAL_REFRESH_OK"
