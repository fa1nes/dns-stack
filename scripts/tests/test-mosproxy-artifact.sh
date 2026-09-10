#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/mosproxy-artifact-common.sh"

EXPECTED="$(mosproxy_expected_version "$ROOT")"

PATCH_COUNT="$(mosproxy_patch_count "$ROOT")"
if [[ ! "$EXPECTED" =~ ^dns-stack/[0-9a-f]{12}-p${PATCH_COUNT}-[0-9a-f]{16}$ ]]; then
    echo "版本串与实际补丁序列不符: $EXPECTED (补丁数 $PATCH_COUNT)" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

cat > "$WORK/good" <<EOF
#!/usr/bin/env bash
printf ' version %s\\n' '$EXPECTED'
EOF
cat > "$WORK/old" <<'EOF'
#!/usr/bin/env bash
echo ' version dev/unknown'
EOF
chmod +x "$WORK/good" "$WORK/old"

mosproxy_binary_matches "$WORK/good" "$EXPECTED"
! mosproxy_binary_matches "$WORK/old" "$EXPECTED"
mosproxy_write_metadata "$WORK/good" "$EXPECTED"
mosproxy_artifact_matches "$WORK/good" "$EXPECTED"

printf 'tampered\n' >> "$WORK/good"
! mosproxy_artifact_matches "$WORK/good" "$EXPECTED"

echo "MOSPROXY_ARTIFACT_OK $EXPECTED"
