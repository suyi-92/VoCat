#!/usr/bin/env bash

set -euo pipefail

tag="${1:?usage: publish-release-assets.sh TAG REPOSITORY DIST_DIR}"
repository="${2:?usage: publish-release-assets.sh TAG REPOSITORY DIST_DIR}"
dist_dir="${3:?usage: publish-release-assets.sh TAG REPOSITORY DIST_DIR}"

archives=(
    vocat-linux-amd64.tar.gz
    vocat-linux-386.tar.gz
    vocat-linux-arm64.tar.gz
    vocat-linux-aarch64.tar.gz
    vocat-linux-armv7.tar.gz
    vocat-windows-amd64.zip
    vocat-windows-arm64.zip
)
checksum=SHA256SUMS
# These are the exact bare-binary names published by the previous workflow.
# Remove them only after the archive set and its checksum manifest commit.
legacy_assets=(
    vocat-linux-amd64
    vocat-linux-386
    vocat-linux-arm64
    vocat-linux-aarch64
    vocat-linux-armv7
    vocat-windows-amd64.exe
    vocat-windows-arm64.exe
)

for asset in "${archives[@]}" "$checksum"; do
    path="$dist_dir/$asset"
    if [ ! -f "$path" ] || [ -L "$path" ] || [ ! -s "$path" ]; then
        echo "required managed release asset is missing, empty, or a symlink: $path" >&2
        exit 1
    fi
done

transaction="$(mktemp -d)"
backup_dir="$transaction/backup"
existing_file="$transaction/existing"
attempted_file="$transaction/attempted"
mkdir -p "$backup_dir"
: > "$attempted_file"
trap 'rm -rf "$transaction"' EXIT
gh release view "$tag" --repo "$repository" \
    --json assets --jq '.assets[].name' > "$existing_file"

asset_existed() {
    grep -Fxq -- "$1" "$existing_file"
}

asset_attempted() {
    grep -Fxq -- "$1" "$attempted_file"
}

for asset in "${archives[@]}" "$checksum"; do
    if asset_existed "$asset"; then
        gh release download "$tag" --repo "$repository" \
            --pattern "$asset" --dir "$backup_dir"
        if [ ! -f "$backup_dir/$asset" ] || [ -L "$backup_dir/$asset" ] || [ ! -s "$backup_dir/$asset" ]; then
            echo "failed to preserve existing release asset before replacement: $asset" >&2
            exit 1
        fi
    fi
done

committed=0
finish_transaction() {
    local status=$?
    trap - EXIT
    if [ "$status" -ne 0 ] && [ "$committed" -eq 0 ] && [ -s "$attempted_file" ]; then
        echo "release asset update failed; restoring the previous managed asset set" >&2
        local rollback_failed=0 asset
        set +e
        # Restore archives first and the checksum manifest last. Until the old
        # manifest is restored, clients fail closed on a hash mismatch.
        for asset in "${archives[@]}"; do
            asset_attempted "$asset" || continue
            if asset_existed "$asset"; then
                gh release upload "$tag" "$backup_dir/$asset" \
                    --repo "$repository" --clobber || rollback_failed=1
            else
                gh release delete-asset "$tag" "$asset" \
                    --repo "$repository" --yes >/dev/null 2>&1 || true
            fi
        done
        if asset_attempted "$checksum"; then
            if asset_existed "$checksum"; then
                gh release upload "$tag" "$backup_dir/$checksum" \
                    --repo "$repository" --clobber || rollback_failed=1
            else
                gh release delete-asset "$tag" "$checksum" \
                    --repo "$repository" --yes >/dev/null 2>&1 || true
            fi
        fi
        set -e
        if [ "$rollback_failed" -ne 0 ]; then
            echo "one or more previous release assets could not be restored" >&2
        fi
    fi
    rm -rf "$transaction"
    exit "$status"
}
trap finish_transaction EXIT

# Replace only the exact archive names managed by this workflow. The previous
# SHA256SUMS remains published while archives change, making partial state fail
# verification. Publish the new manifest last as the commit point.
for asset in "${archives[@]}"; do
    printf '%s\n' "$asset" >> "$attempted_file"
    gh release upload "$tag" "$dist_dir/$asset" \
        --repo "$repository" --clobber
done
printf '%s\n' "$checksum" >> "$attempted_file"
gh release upload "$tag" "$dist_dir/$checksum" \
    --repo "$repository" --clobber
committed=1

# Preserve signatures, SBOMs, and any other manually managed attachments.
# Only the seven legacy names below belong to the old bare-binary workflow.
cleanup_failed=0
for asset in "${legacy_assets[@]}"; do
    asset_existed "$asset" || continue
    if ! gh release delete-asset "$tag" "$asset" \
        --repo "$repository" --yes; then
        echo "warning: could not remove obsolete managed asset $asset" >&2
        cleanup_failed=1
    fi
done
if [ "$cleanup_failed" -ne 0 ]; then
    echo "warning: release assets committed; obsolete-asset cleanup can be retried safely" >&2
fi
exit 0
