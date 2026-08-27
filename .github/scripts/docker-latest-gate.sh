#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C

image="${1:?usage: docker-latest-gate.sh GHCR_IMAGE VERSION}"
version="${2:?usage: docker-latest-gate.sh GHCR_IMAGE VERSION}"
attempts="${GHCR_GATE_ATTEMPTS:-6}"
retry_seconds="${GHCR_GATE_RETRY_SECONDS:-5}"
stable_pattern='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

[[ "$version" =~ $stable_pattern ]] || {
    echo "latest promotion requires a strict stable SemVer, got: $version" >&2
    exit 1
}
[[ "$attempts" =~ ^[1-9][0-9]*$ ]] || {
    echo "GHCR_GATE_ATTEMPTS must be a positive integer" >&2
    exit 1
}
[[ "$retry_seconds" =~ ^[0-9]+$ ]] || {
    echo "GHCR_GATE_RETRY_SECONDS must be a non-negative integer" >&2
    exit 1
}

case "$image" in
    ghcr.io/*/*) image_path="${image#ghcr.io/}" ;;
    *) echo "expected a ghcr.io/owner/package image, got: $image" >&2; exit 1 ;;
esac
owner="${image_path%%/*}"
package="${image_path#*/}"
if [ -z "$owner" ] || [ -z "$package" ] || [[ "$package" == */* ]]; then
    echo "expected a single GHCR owner/package path, got: $image" >&2
    exit 1
fi

owner_type=$(gh api "/users/$owner" --jq '.type') || {
    echo "could not determine GHCR package owner type; refusing to update latest" >&2
    exit 1
}
case "$owner_type" in
    Organization) endpoint="/orgs/$owner/packages/container/$package/versions" ;;
    User) endpoint="/users/$owner/packages/container/$package/versions" ;;
    *) echo "unsupported GitHub package owner type: $owner_type" >&2; exit 1 ;;
esac

tags=""
visible=0
for ((attempt = 1; attempt <= attempts; attempt++)); do
    if tags=$(gh api --paginate "$endpoint?per_page=100" \
        --jq '.[].metadata.container.tags[]?' 2>/dev/null); then
        if grep -Fxq -- "$version" <<<"$tags"; then
            visible=1
            break
        fi
    fi
    if [ "$attempt" -lt "$attempts" ]; then
        sleep "$retry_seconds"
    fi
done
[ "$visible" -eq 1 ] || {
    echo "GHCR query failed or immutable tag $version was not visible; refusing to update latest" >&2
    exit 1
}

numeric_component_greater() {
    local left="$1" right="$2"
    if [ "${#left}" -ne "${#right}" ]; then
        [ "${#left}" -gt "${#right}" ]
        return
    fi
    [[ "$left" > "$right" ]]
}

semver_greater() {
    local left="$1" right="$2"
    local left_major left_minor left_patch right_major right_minor right_patch
    IFS=. read -r left_major left_minor left_patch <<<"$left"
    IFS=. read -r right_major right_minor right_patch <<<"$right"
    local -a left_parts=("$left_major" "$left_minor" "$left_patch")
    local -a right_parts=("$right_major" "$right_minor" "$right_patch")
    local index left_part right_part
    for index in 0 1 2; do
        left_part="${left_parts[$index]}"
        right_part="${right_parts[$index]}"
        [ "$left_part" = "$right_part" ] && continue
        numeric_component_greater "$left_part" "$right_part"
        return
    done
    return 1
}

while IFS= read -r published; do
    [[ "$published" =~ $stable_pattern ]] || continue
    if semver_greater "$published" "$version"; then
        echo "GHCR already contains newer stable tag $published; refusing to move latest to $version" >&2
        exit 1
    fi
done <<<"$tags"

echo "GHCR latest promotion authorized for $image:$version"
