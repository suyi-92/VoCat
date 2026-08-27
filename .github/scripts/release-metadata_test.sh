#!/usr/bin/env bash

set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
parser="$script_dir/release-metadata.sh"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT

assert_output() {
    local ref_type="$1"
    local ref_name="$2"
    local expected_release="$3"
    local expected_version="$4"
    local expected_prerelease="$5"
    local output="$test_root/output"
    : > "$output"
    GITHUB_OUTPUT="$output" bash "$parser" "$ref_type" "$ref_name"
    grep -Fxq "is_release=$expected_release" "$output"
    grep -Fxq "version=$expected_version" "$output"
    grep -Fxq "prerelease=$expected_prerelease" "$output"
}

assert_failure() {
    local ref_name="$1"
    local output="$test_root/output"
    : > "$output"
    if GITHUB_OUTPUT="$output" bash "$parser" tag "$ref_name" >/dev/null 2>&1; then
        echo "release metadata parser accepted invalid tag: $ref_name" >&2
        exit 1
    fi
}

assert_ref_failure() {
    local ref_type="$1"
    local ref_name="$2"
    local output="$test_root/output"
    : > "$output"
    if GITHUB_OUTPUT="$output" bash "$parser" "$ref_type" "$ref_name" >/dev/null 2>&1; then
        echo "release metadata parser accepted unsupported ref: $ref_type/$ref_name" >&2
        exit 1
    fi
}

assert_output branch codex/windows false 0.0.0-dev false
assert_output tag v0.0.0 true 0.0.0 false
assert_output tag v1.2.3 true 1.2.3 false
assert_output tag v1.2.3-rc.1 true 1.2.3-rc.1 true
assert_output tag v1.2.3-alpha.01a true 1.2.3-alpha.01a true

for invalid in \
    1.2.3 \
    v1.2 \
    v01.2.3 \
    v1.02.3 \
    v1.2.03 \
    v1.2.3- \
    v1.2.3-01 \
    v1.2.3-alpha..1 \
    v1.2.3+build.1; do
    assert_failure "$invalid"
done

assert_ref_failure pull_request anything

echo "release metadata tests passed"
