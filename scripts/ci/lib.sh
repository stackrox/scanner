#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
source "$ROOT/scripts/lib.sh"

# A library of CI related reusable bash functions

set -euo pipefail

push_images() {
    info "Pushing images"

    if [[ "$#" -ne 1 ]]; then
        die "missing arg. usage: push_images <ci_tag>"
    fi

    require_environment "DOCKER_IO_PUSH_USERNAME"
    require_environment "DOCKER_IO_PUSH_PASSWORD"
    require_environment "QUAY_RHACS_ENG_RW_USERNAME"
    require_environment "QUAY_RHACS_ENG_RW_PASSWORD"
    require_environment "QUAY_STACKROX_IO_RW_USERNAME"
    require_environment "QUAY_STACKROX_IO_RW_PASSWORD"

    local ci_tag="$1"
    local tag
    tag="$(make --quiet --no-print-directory tag)"
    local image_set=("scanner" "scanner-db" "scanner-slim" "scanner-db-slim")

    _push_image_set() {
        local registry="$1"
        local tag="$2"

        for image in "${image_set[@]}"; do
            "$ROOT/scripts/push-as-manifest-list.sh" "${registry}/${image}:${tag}" | cat
        done
    }

    _tag_image_set() {
        local registry="$1"
        local tag="$2"

        for image in "${image_set[@]}"; do
            docker tag "${image}:${tag}" "${registry}/${image}:${tag}"
        done
    }

    # Push to us.gcr.io/stackrox-ci
    _tag_image_set "us.gcr.io/stackrox-ci" "$tag"
    _push_image_set "us.gcr.io/stackrox-ci" "$tag"

    # Push to docker.io/stackrox
    docker login -u "$DOCKER_IO_PUSH_USERNAME" --password-stdin <<<"$DOCKER_IO_PUSH_PASSWORD" docker.io
    _tag_image_set "stackrox" "$tag"
    _push_image_set "stackrox" "$tag"

    # Push to quay.io/rhacs-eng
    docker login -u "$QUAY_RHACS_ENG_RW_USERNAME" --password-stdin <<<"$QUAY_RHACS_ENG_RW_PASSWORD" quay.io
    _tag_image_set "quay.io/rhacs-eng" "$tag"
    _push_image_set "quay.io/rhacs-eng" "$tag"

    # Push to quay.io/stackrox-io
    docker login -u "$QUAY_STACKROX_IO_RW_USERNAME" --password-stdin <<<"$QUAY_STACKROX_IO_RW_PASSWORD" quay.io
    _tag_image_set "quay.io/stackrox-io" "$tag"
    _push_image_set "quay.io/stackrox-io" "$tag"

    if [[ -n "$ci_tag" ]]; then
        require_environment "STACKROX_IO_PUSH_USERNAME"
        require_environment "STACKROX_IO_PUSH_PASSWORD"
        docker login -u "$STACKROX_IO_PUSH_USERNAME" --password-stdin <<<"$STACKROX_IO_PUSH_PASSWORD" stackrox.io

        _tag_image_set "stackrox.io" "$tag"
        _push_image_set "stackrox.io" "$tag"
    fi
}
