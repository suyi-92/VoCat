#!/usr/bin/env bash

set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
publisher="$script_dir/publish-release-assets.sh"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT
mkdir -p "$test_root/bin"

cat > "$test_root/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

[ "${1:-}" = release ] || exit 2
operation="${2:-}"
shift 2
case "$operation" in
    view)
        for path in "$MOCK_REMOTE"/*; do
            [ -f "$path" ] || continue
            basename "$path"
        done
        ;;
    download)
        pattern=""
        destination=""
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --pattern) pattern="$2"; shift 2 ;;
                --dir) destination="$2"; shift 2 ;;
                *) shift ;;
            esac
        done
        [ -n "$pattern" ] && [ -n "$destination" ]
        cp "$MOCK_REMOTE/$pattern" "$destination/$pattern"
        ;;
    upload)
        tag="$1"
        path="$2"
        name="${path##*/}"
        printf 'upload:%s\n' "$name" >> "$MOCK_LOG"
        if [ "${MOCK_FAIL_ASSET:-}" = "$name" ] && [ ! -e "$MOCK_FAIL_MARKER" ]; then
            rm -f "$MOCK_REMOTE/$name"
            : > "$MOCK_FAIL_MARKER"
            exit 1
        fi
        cp "$path" "$MOCK_REMOTE/$name"
        ;;
    delete-asset)
        tag="$1"
        name="$2"
        printf 'delete:%s\n' "$name" >> "$MOCK_LOG"
        rm -f "$MOCK_REMOTE/$name"
        ;;
    *) exit 2 ;;
esac
EOF
chmod 0755 "$test_root/bin/gh"

archives=(
    vocat-linux-amd64.tar.gz
    vocat-linux-386.tar.gz
    vocat-linux-arm64.tar.gz
    vocat-linux-aarch64.tar.gz
    vocat-linux-armv7.tar.gz
    vocat-windows-amd64.zip
    vocat-windows-arm64.zip
)

prepare_fixture() {
    local name="$1"
    FIXTURE="$test_root/$name"
    DIST="$FIXTURE/dist"
    REMOTE="$FIXTURE/remote"
    LOG="$FIXTURE/gh.log"
    mkdir -p "$DIST" "$REMOTE"
    : > "$LOG"
    local asset
    for asset in "${archives[@]}"; do
        printf 'new:%s\n' "$asset" > "$DIST/$asset"
        printf 'old:%s\n' "$asset" > "$REMOTE/$asset"
    done
    printf '%s\n' new-checksums > "$DIST/SHA256SUMS"
    printf '%s\n' old-checksums > "$REMOTE/SHA256SUMS"
    printf '%s\n' manual-signature > "$REMOTE/vocat-linux-amd64.tar.gz.sig"
    printf '%s\n' old-binary > "$REMOTE/vocat-linux-amd64"
}

prepare_fixture success
PATH="$test_root/bin:$PATH" MOCK_REMOTE="$REMOTE" MOCK_LOG="$LOG" \
    MOCK_FAIL_MARKER="$FIXTURE/fail.once" \
    bash "$publisher" v1.2.3 owner/repo "$DIST"
for asset in "${archives[@]}" SHA256SUMS; do
    cmp "$DIST/$asset" "$REMOTE/$asset"
done
[ -f "$REMOTE/vocat-linux-amd64.tar.gz.sig" ] || {
    echo "publisher deleted a manually managed signature" >&2
    exit 1
}
[ ! -e "$REMOTE/vocat-linux-amd64" ] || {
    echo "publisher retained an obsolete managed bare binary" >&2
    exit 1
}
[ "$(grep '^upload:' "$LOG" | tail -n 1)" = 'upload:SHA256SUMS' ] || {
    echo "checksum manifest was not uploaded last" >&2
    exit 1
}

prepare_fixture rollback
PATH="$test_root/bin:$PATH" MOCK_REMOTE="$REMOTE" MOCK_LOG="$LOG" \
    MOCK_FAIL_ASSET=vocat-linux-arm64.tar.gz \
    MOCK_FAIL_MARKER="$FIXTURE/fail.once" \
    bash "$publisher" v1.2.3 owner/repo "$DIST" >/dev/null 2>&1 && {
        echo "publisher unexpectedly succeeded after an injected upload failure" >&2
        exit 1
    }
for asset in "${archives[@]}"; do
    expected="old:$asset"
    [ "$(sed -n '1p' "$REMOTE/$asset")" = "$expected" ] || {
        echo "rollback did not restore $asset" >&2
        exit 1
    }
done
[ "$(sed -n '1p' "$REMOTE/SHA256SUMS")" = old-checksums ] || {
    echo "rollback did not preserve the old checksum manifest" >&2
    exit 1
}
[ -f "$REMOTE/vocat-linux-amd64.tar.gz.sig" ] || {
    echo "rollback deleted a manually managed signature" >&2
    exit 1
}

echo "release asset publisher tests passed"
