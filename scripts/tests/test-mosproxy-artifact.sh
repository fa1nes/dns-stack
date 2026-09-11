#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/mosproxy-artifact-common.sh"

EXPECTED="$(mosproxy_expected_version "$ROOT")"
REPO="$(mosproxy_expected_repo "$ROOT")"

if [[ ! "$EXPECTED" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "artifact_version 不是 vX.Y.Z: $EXPECTED" >&2
    exit 1
fi
if [[ ! "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    echo "repo 不是 owner/name: $REPO" >&2
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

echo "MOSPROXY_ARTIFACT_OK $REPO $EXPECTED"
