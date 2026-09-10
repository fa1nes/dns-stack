#!/usr/bin/env bash

set -o pipefail

mosproxy_lock_value() {
    local root="$1" key="$2"
    sed -n '/"mosproxy"[[:space:]]*:/,$p' "$root/versions.lock" \
        | grep -m1 "\"${key}\"[[:space:]]*:" \
        | sed -E 's/.*:[[:space:]]*//; s/,[[:space:]]*$//; s/^"//; s/"$//'
}

mosproxy_patch_count() {
    local root="$1" patch count=0
    for patch in "$root"/patches/mosproxy-commits/*.patch; do
        [[ -e "$patch" ]] || continue
        count=$((count + 1))
    done
    printf '%s\n' "$count"
}

mosproxy_patch_series_hash() {
    local root="$1" patch sum count=0
    local manifest=""

    for patch in "$root"/patches/mosproxy-commits/*.patch; do
        [[ -e "$patch" ]] || continue
        sum="$(sha256sum "$patch" | awk '{print $1}')" || return 1
        manifest+="${sum}  $(basename "$patch")"$'\n'
        count=$((count + 1))
    done
    [[ "$count" -gt 0 ]] || return 1
    printf '%s' "$manifest" | sha256sum | awk '{print $1}'
}

mosproxy_expected_version() {
    local root="$1" pin expected_count actual_count series_hash locked_hash locked_version version
    pin="$(mosproxy_lock_value "$root" pinned_commit)"
    locked_hash="$(mosproxy_lock_value "$root" patch_series_sha256)"
    locked_version="$(mosproxy_lock_value "$root" artifact_version)"
    expected_count="$(mosproxy_lock_value "$root" local_patch_count)"
    actual_count="$(mosproxy_patch_count "$root")"
    series_hash="$(mosproxy_patch_series_hash "$root")"

    [[ "$pin" =~ ^[0-9a-fA-F]{40}$ ]] || return 1
    [[ "$expected_count" =~ ^[0-9]+$ ]] || return 1
    [[ "$actual_count" == "$expected_count" ]] || return 1
    [[ "$series_hash" =~ ^[0-9a-f]{64}$ ]] || return 1
    [[ "$series_hash" == "$locked_hash" ]] || return 1
    version="dns-stack/${pin:0:12}-p${actual_count}-${series_hash:0:16}"
    [[ "$version" == "$locked_version" ]] || return 1
    printf '%s\n' "$version"
}

mosproxy_binary_matches() {
    local binary="$1" expected="$2" output
    [[ -x "$binary" && -n "$expected" ]] || return 1
    output="$("$binary" --version 2>&1)" || return 1
    [[ "$output" == *"$expected"* ]]
}

mosproxy_checksum_matches() {
    local binary="$1" checksum_file="$2" expected actual
    [[ -s "$binary" && -s "$checksum_file" ]] || return 1
    expected="$(awk 'NR == 1 {print $1}' "$checksum_file")"
    actual="$(sha256sum "$binary" | awk '{print $1}')"
    [[ "$expected" =~ ^[0-9a-fA-F]{64}$ && "${expected,,}" == "$actual" ]]
}

mosproxy_artifact_matches() {
    local binary="$1" expected="$2" build_id_file="${1}.build-id"
    [[ -s "$build_id_file" ]] || return 1
    [[ "$(tr -d '\r\n' < "$build_id_file")" == "$expected" ]] || return 1
    mosproxy_checksum_matches "$binary" "${binary}.sha256" || return 1
    mosproxy_binary_matches "$binary" "$expected"
}

mosproxy_write_metadata() {
    local binary="$1" expected="$2" name
    name="$(basename "$binary")"
    printf '%s\n' "$expected" > "${binary}.build-id"
    printf '%s  %s\n' "$(sha256sum "$binary" | awk '{print $1}')" "$name" \
        > "${binary}.sha256"
    chmod 0644 "${binary}.build-id" "${binary}.sha256"
}
