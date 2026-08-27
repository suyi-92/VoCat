#!/usr/bin/env bash

set -euo pipefail

ref_type="${1:?usage: release-metadata.sh REF_TYPE REF_NAME}"
ref_name="${2:?usage: release-metadata.sh REF_TYPE REF_NAME}"
output_path="${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

is_release=false
version="0.0.0-dev"
prerelease=false

case "$ref_type" in
    branch)
        ;;
    tag)
        is_release=true
        if [[ "$ref_name" != v* ]]; then
            echo "::error title=Invalid release tag::Release tags must start with v." >&2
            exit 1
        fi
        version="${ref_name#v}"
        if [[ "$version" == *+* ]]; then
            echo "::error title=Unsupported release tag::SemVer build metadata (+build) is not supported because it cannot be represented as a GHCR tag." >&2
            exit 1
        fi
        # Strict SemVer core and prerelease grammar. Numeric prerelease
        # identifiers may not contain leading zeroes; non-numeric identifiers
        # must contain at least one ASCII letter or hyphen.
        semver_pattern='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?$'
        if [[ ! "$version" =~ $semver_pattern ]]; then
            echo "::error title=Invalid release tag::$ref_name is not a strict SemVer release tag (expected vMAJOR.MINOR.PATCH[-PRERELEASE])." >&2
            exit 1
        fi
        if [[ "$version" == *-* ]]; then
            prerelease=true
        fi
        ;;
    *)
        echo "::error title=Unsupported Git ref::Expected a branch or tag ref, got $ref_type." >&2
        exit 1
        ;;
esac

{
    echo "is_release=$is_release"
    echo "version=$version"
    echo "prerelease=$prerelease"
} >> "$output_path"
