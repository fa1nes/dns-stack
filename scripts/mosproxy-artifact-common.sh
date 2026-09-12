#!/usr/bin/env bash

set -o pipefail

mosproxy_lock_value() {
    local root="$1" key="$2"
    sed -n '/"mosproxy"[[:space:]]*:/,$p' "$root/versions.lock" \
        | grep -m1 "\"${key}\"[[:space:]]*:" \
        | sed -E 's/.*:[[:space:]]*//; s/,[[:space:]]*$//; s/^"//; s/"$//'
}

mosproxy_artifact_version() {
    local binary="$1" version
    [[ -s "${binary}.build-id" ]] || return 1
    version="$(tr -d '\r\n' < "${binary}.build-id")"
    [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    printf '%s\n' "$version"
}

mosproxy_installed_version() {
    local binary="$1" output version
    [[ -x "$binary" ]] || return 1
    output="$("$binary" --version 2>&1)" || return 1
    version="$(grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' <<<"$output" | head -1)"
    [[ -n "$version" ]] || return 1
    printf '%s\n' "$version"
}

mosproxy_expected_repo() {
    local root="$1" repo
    repo="$(mosproxy_lock_value "$root" repo)"
    [[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || return 1
    printf '%s\n' "$repo"
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
