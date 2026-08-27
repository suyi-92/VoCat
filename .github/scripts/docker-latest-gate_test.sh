#!/usr/bin/env bash

set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
gate="$script_dir/docker-latest-gate.sh"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT
mkdir -p "$test_root/bin"

cat > "$test_root/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${2:-}" = /users/owner ]; then
    printf '%s\n' Organization
    exit 0
fi
[ "${MOCK_GH_FAIL:-0}" = 0 ] || exit 1
printf '%s\n' "${MOCK_TAGS:-}"
EOF
chmod 0755 "$test_root/bin/gh"

run_gate() {
    PATH="$test_root/bin:$PATH" \
        GHCR_GATE_ATTEMPTS=1 \
        GHCR_GATE_RETRY_SECONDS=0 \
        MOCK_TAGS="$1" \
        MOCK_GH_FAIL="${2:-0}" \
        bash "$gate" ghcr.io/owner/repo "$3"
}

run_gate $'1.9.1\n2.0.0\nlatest\n2.1.0-rc.1' 0 2.0.0 >/dev/null
run_gate $'99999999999999999998.0.0\n99999999999999999999.0.0' \
    0 99999999999999999999.0.0 >/dev/null
if run_gate $'1.9.1\n2.0.0' 0 1.9.1 >/dev/null 2>&1; then
    echo "latest gate accepted a stable downgrade" >&2
    exit 1
fi
if run_gate '2.0.0' 1 2.0.0 >/dev/null 2>&1; then
    echo "latest gate failed open when the GHCR query failed" >&2
    exit 1
fi
if run_gate '2.0.0' 0 2.0.0-rc.1 >/dev/null 2>&1; then
    echo "latest gate accepted a prerelease" >&2
    exit 1
fi
if run_gate '1.9.1' 0 2.0.0 >/dev/null 2>&1; then
    echo "latest gate accepted a target tag that was not visible in GHCR" >&2
    exit 1
fi

echo "docker latest gate tests passed"
