#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/mosproxy-artifact-common.sh"

REPO="$(mosproxy_expected_repo "$ROOT")"
if [[ ! "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    echo "versions.lock 的 repo 不是 owner/name: $REPO" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

VERSION="v9.8.7"
cat > "$WORK/mosproxy" <<EOF
#!/usr/bin/env bash
printf ' version %s\\n' '$VERSION'
EOF
chmod +x "$WORK/mosproxy"
mosproxy_write_metadata "$WORK/mosproxy" "$VERSION"

got="$(mosproxy_artifact_version "$WORK/mosproxy")"
[[ "$got" == "$VERSION" ]] || { echo "版本应当从 build-id 读出，得到 $got" >&2; exit 1; }

got="$(mosproxy_installed_version "$WORK/mosproxy")"
[[ "$got" == "$VERSION" ]] || { echo "版本应当能从 --version 读出，得到 $got" >&2; exit 1; }

mosproxy_artifact_matches "$WORK/mosproxy" "$VERSION"

printf 'tampered\n' >> "$WORK/mosproxy"
! mosproxy_artifact_matches "$WORK/mosproxy" "$VERSION"

printf 'not-a-version\n' > "$WORK/mosproxy.build-id"
! mosproxy_artifact_version "$WORK/mosproxy"

rm -f "$WORK/mosproxy.build-id"
! mosproxy_artifact_version "$WORK/mosproxy"

cat > "$WORK/old" <<'EOF'
#!/usr/bin/env bash
echo ' version dns-stack/80afb0117d50-p16-25d24786b7d94d9b'
EOF
chmod +x "$WORK/old"
! mosproxy_installed_version "$WORK/old"

echo "MOSPROXY_ARTIFACT_OK $REPO (版本随 Release 走，不写死)"
