#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/state/sync-state" "$TMP/bin"
cat > "$TMP/state/polluted-ip.txt" <<'EOF'
# legacy confirmed addresses
1.2.3.4
2001:db8::1
EOF
cat > "$TMP/state/sync-state/polluted-ip-cidr.remote.txt" <<'EOF'
8.8.8.8/32
2001:4860::/32
EOF
printf '9.9.9.9/32\n' > "$TMP/state/sync-state/polluted-ip-cidr.local.txt"
cat > "$TMP/bin/dig" <<'EOF'
#!/usr/bin/env bash
if [[ " $* " == *" +comments "* ]]; then
    echo ';; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1'
    exit 0
fi
if [[ "${DIG_SAMPLE:-0}" == "1" ]]; then
    echo "6.6.6.6"
fi
if [[ "${DIG_SINGLE_SAMPLE:-0}" == "1" ]]; then
    marker="${TMPDIR:-/tmp}/dns-single-sample-seen"
    if [[ ! -e "$marker" ]]; then
        : > "$marker"
        echo "7.7.7.7"
    fi
fi
exit 0
EOF
chmod +x "$TMP/bin/dig"
cat > "$TMP/bin/python3" <<'EOF'
#!/usr/bin/env bash
exec "${TEST_PYTHON:-/usr/bin/python3}" "$@"
EOF
chmod +x "$TMP/bin/python3"

PATH="$TMP/bin:$PATH" STATE_DIR="$TMP/state" ROUNDS=1 \
    bash "$ROOT/scripts/collect-polluted-ip.sh" >/dev/null

grep -qx '1.2.3.4/32' "$TMP/state/sync-state/polluted-ip-cidr.local.txt"
grep -qx '2001:db8::1/128' "$TMP/state/sync-state/polluted-ip-cidr.local.txt"
! grep -qx '8.8.8.8/32' "$TMP/state/sync-state/polluted-ip-cidr.local.txt"
! grep -qx '9.9.9.9/32' "$TMP/state/sync-state/polluted-ip-cidr.local.txt"
grep -qx '8.8.8.8/32' "$TMP/state/sync-state/polluted-ip-cidr.remote.txt"
! grep -qE '1\.2\.3\.0/|2001:db8::/' "$TMP/state/sync-state/polluted-ip-cidr.local.txt"

mkdir -p "$TMP/empty-state/sync-state"
: > "$TMP/empty-state/polluted-ip.txt"
DIG_SAMPLE=1 PATH="$TMP/bin:$PATH" STATE_DIR="$TMP/empty-state" ROUNDS=1 \
    bash "$ROOT/scripts/collect-polluted-ip.sh" >/dev/null
grep -qx '6.6.6.6' "$TMP/empty-state/polluted-ip.txt"
grep -qx '6.6.6.6/32' "$TMP/empty-state/sync-state/polluted-ip-cidr.local.txt"
grep -q '# 本次新增: 1    累计: 1' "$TMP/empty-state/polluted-ip.txt"

mkdir -p "$TMP/single-state/sync-state" "$TMP/single-tmp"
DIG_SINGLE_SAMPLE=1 TMPDIR="$TMP/single-tmp" PATH="$TMP/bin:$PATH" \
    STATE_DIR="$TMP/single-state" ROUNDS=1 \
    bash "$ROOT/scripts/collect-polluted-ip.sh" >/dev/null
! grep -qx '7.7.7.7' "$TMP/single-state/polluted-ip.txt"
! grep -qx '7.7.7.7/32' "$TMP/single-state/sync-state/polluted-ip-cidr.local.txt"

echo "COLLECT_POLLUTED_IP_OK"
