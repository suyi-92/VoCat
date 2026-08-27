#!/usr/bin/env bash

set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(CDPATH= cd -- "$script_dir/../.." && pwd)"
installer="$repository_root/scripts/install.sh"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT

VOCAT_INSTALL_LIBRARY_ONLY=1 source "$installer"

assert_candidate_version() {
    local output="$1"
    local expected="$2"
    local actual
    actual=$(candidate_version_from_output "$output")
    [ "$actual" = "$expected" ] || {
        echo "candidate version = $actual, want $expected" >&2
        exit 1
    }
}

assert_candidate_version "vocat 1.2.3" "1.2.3"
assert_candidate_version "vocat 1.2.3-rc.1 (2026-08-27T10:11:12Z)" "1.2.3-rc.1"
if candidate_version_from_output $'warning\nvocat 1.2.3' >/dev/null 2>&1; then
    echo "candidate parser accepted extra output" >&2
    exit 1
fi
if candidate_version_from_output "vocat 1.2.3-alpha..1" >/dev/null 2>&1; then
    echo "candidate parser accepted invalid SemVer" >&2
    exit 1
fi

# Exercise the archive path with an executable that is valid for the host but
# reports a different version. The archive itself is structurally valid; the
# candidate/version binding must be the operation that rejects it.
fixture="$test_root/wrong-version"
mkdir -p "$fixture/package/LICENSES" "$fixture/work"
cat > "$fixture/package/vocat-linux-amd64" <<'EOF'
#!/bin/sh
[ "${1:-}" = version ] || exit 2
printf '%s\n' 'vocat 1.2.2'
EOF
chmod 0755 "$fixture/package/vocat-linux-amd64"
printf '%s\n' license > "$fixture/package/LICENSE"
printf '%s\n' notice > "$fixture/package/NOTICE"
printf '%s\n' third-party > "$fixture/package/LICENSES/example.txt"
tar -C "$fixture/package" -czf "$fixture/vocat-linux-amd64.tar.gz" \
    vocat-linux-amd64 LICENSE NOTICE LICENSES
VOCAT_TMP="$fixture/work"
validate_and_extract_archive "$fixture/vocat-linux-amd64.tar.gz" vocat-linux-amd64
if validate_candidate_binary "$VOCAT_TMP/vocat" 1.2.3; then
    echo "installer accepted an archive whose binary reports the wrong version" >&2
    exit 1
fi

# The lock is machine-wide in production and path-overridable only for this
# isolated fixture. A second process must fail while the holder owns it, and a
# normal holder exit must make the lock immediately acquirable again.
lock_dir="$test_root/vocat-install.lock"
ready="$test_root/ready"
hold="$test_root/hold"
: > "$hold"
VOCAT_INSTALL_LIBRARY_ONLY=1 VOCAT_INSTALL_LOCK_DIR="$lock_dir" \
    bash -c '
        source "$1"
        acquire_install_lock
        trap "release_install_lock" EXIT
        : > "$2"
        while [ -e "$3" ]; do sleep 0.05; done
    ' _ "$installer" "$ready" "$hold" &
holder_pid=$!
for _ in $(seq 1 100); do
    [ -e "$ready" ] && break
    sleep 0.05
done
[ -e "$ready" ] || {
    echo "lock holder did not become ready" >&2
    kill "$holder_pid" 2>/dev/null || true
    wait "$holder_pid" 2>/dev/null || true
    exit 1
}
if VOCAT_INSTALL_LIBRARY_ONLY=1 VOCAT_INSTALL_LOCK_DIR="$lock_dir" \
    bash -c 'source "$1"; acquire_install_lock' _ "$installer"; then
    echo "concurrent installer unexpectedly acquired the transaction lock" >&2
    exit 1
fi
rm -f "$hold"
wait "$holder_pid"
[ ! -e "$lock_dir" ] || {
    echo "installer lock was not released on normal exit" >&2
    exit 1
}

INSTALL_LOCK_DIR="$lock_dir"
INSTALL_LOCK_HELD=0
acquire_install_lock
release_install_lock

echo "installer helper tests passed"
