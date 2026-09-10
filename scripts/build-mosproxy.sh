#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/mosproxy-artifact-common.sh"

ARCH="all"
OUTPUT_DIR="$PROJECT_ROOT/bin"
RUN_TESTS=1

usage() {
    echo "用法: bash scripts/build-mosproxy.sh [--arch amd64|arm64|all] [--output-dir 目录] [--skip-tests]"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch) ARCH="${2:-}"; shift 2 ;;
        --output-dir) OUTPUT_DIR="${2:-}"; shift 2 ;;
        --skip-tests) RUN_TESTS=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "未知参数: $1" >&2; usage >&2; exit 2 ;;
    esac
done

case "$ARCH" in
    amd64|arm64) ARCHES=("$ARCH") ;;
    all) ARCHES=(amd64 arm64) ;;
    *) echo "不支持的架构: $ARCH" >&2; exit 2 ;;
esac

GO_BIN="${GO:-go}"
command -v git >/dev/null 2>&1 || { echo "缺少 git" >&2; exit 1; }
command -v "$GO_BIN" >/dev/null 2>&1 || { echo "缺少 Go: $GO_BIN" >&2; exit 1; }

PIN="$(mosproxy_lock_value "$PROJECT_ROOT" pinned_commit)"
REPO="$(mosproxy_lock_value "$PROJECT_ROOT" repo)"
EXPECTED_VERSION="$(mosproxy_expected_version "$PROJECT_ROOT")" || {
    echo "versions.lock 与 mosproxy 补丁序列不一致" >&2
    exit 1
}

WORK="$(mktemp -d "${TMPDIR:-/tmp}/dns-stack-mosproxy.XXXXXX")"
cleanup() { rm -rf -- "$WORK"; }
trap cleanup EXIT

git clone -q "$REPO" "$WORK/src"
git -C "$WORK/src" checkout -q --detach "$PIN"
for patch in "$PROJECT_ROOT"/patches/mosproxy-commits/*.patch; do
    [[ -e "$patch" ]] || continue
    git -C "$WORK/src" apply --check "$patch"
    git -C "$WORK/src" apply "$patch"
done
git -C "$WORK/src" diff --check

if [[ "$RUN_TESTS" -eq 1 ]]; then
    (cd "$WORK/src" && "$GO_BIN" test ./...)
fi

mkdir -p "$OUTPUT_DIR"
for arch in "${ARCHES[@]}"; do
    name="mosproxy-linux-${arch}"
    staged="$WORK/${name}"
    (
        cd "$WORK/src"
        CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$GO_BIN" build \
            -trimpath -buildvcs=false \
            -ldflags "-s -w -X main.version=${EXPECTED_VERSION}" \
            -o "$staged" .
    )
    chmod 0755 "$staged"
    mv -f "$staged" "$OUTPUT_DIR/$name"
    mosproxy_write_metadata "$OUTPUT_DIR/$name" "$EXPECTED_VERSION"
    echo "已生成: $OUTPUT_DIR/$name (${EXPECTED_VERSION})"
done
