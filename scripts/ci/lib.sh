#!/usr/bin/env bash

set -euo pipefail

# A library of CI related reusable bash functions

set +u
SCRIPTS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
set -u

source "$SCRIPTS_ROOT/scripts/lib.sh"

get_pr_details() {
    local pull_request
    local org
    local repo

    if is_CIRCLECI; then
        [ -n "${CIRCLE_PULL_REQUEST}" ] || { echo "Not on a PR, ignoring label overrides"; exit 3; }
        [ -n "${CIRCLE_PROJECT_USERNAME}" ] || { echo "CIRCLE_PROJECT_USERNAME not found" ; exit 2; }
        [ -n "${CIRCLE_PROJECT_REPONAME}" ] || { echo "CIRCLE_PROJECT_REPONAME not found" ; exit 2; }
        pull_request="${CIRCLE_PULL_REQUEST}"
        org="${CIRCLE_PROJECT_USERNAME}"
        repo="${CIRCLE_PROJECT_REPONAME}"
    else
        die "not supported"
    fi

    local headers=()
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        headers+=(-H "Authorization: token ${GITHUB_TOKEN}")
    fi

    local url="https://api.github.com/repos/${org}/${repo}/pulls/${pull_request}"
    curl -sS "${headers[@]}" "${url}"
}

pr_has_label() {
    if [[ -z "${1:-}" ]]; then
        die "usage: pr_has_label <expected label>"
    fi

    local expected_label="$1"
    get_pr_details | jq '([.labels | .[].name]  // []) | .[]' -r | grep -qx "${expected_label}"
}

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
            "$SCRIPTS_ROOT/scripts/push-as-manifest-list.sh" "${registry}/${image}:${tag}" | cat
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
