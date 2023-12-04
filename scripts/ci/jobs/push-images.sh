#!/usr/bin/env bash

# Adapted from https://github.com/stackrox/stackrox/blob/master/scripts/ci/jobs/push-images.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
# shellcheck source=../../../scripts/ci/lib.sh
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

push_images() {
    info "Will push images built in CI"

    info "Images from OpenShift CI builds:"
    env | grep IMAGE || true

    [[ "${OPENSHIFT_CI:-false}" == "true" ]] || { die "Only supported in OpenShift CI"; }

    push_image_set

    if is_in_PR_context; then
        comment_on_pr || {
            warn "Could not add a comment to the PR"
        }
    fi
}

comment_on_pr() {
    info "Adding a comment with the build tag to the PR"

    local pr_details
    local exitstatus=0
    pr_details="$(get_pr_details)" || exitstatus="$?"
    if [[ "$exitstatus" != "0" ]]; then
        debug "Unable to get the PR details from GitHub: $exitstatus"
        debug "PR details: ${pr_details}"
        info "Will continue without commenting on the PR"
        return
    fi

    # hub-comment is tied to Circle CI env
    local url
    url=$(jq -r '.html_url' <<<"$pr_details")
    export CIRCLE_PULL_REQUEST="$url"

    local sha
    sha=$(jq -r '.head.sha' <<<"$pr_details")
    sha=${sha:0:7}
    export _SHA="$sha"

    local tag
    tag=$(make tag)
    export _TAG="$tag"

    local tmpfile
    tmpfile=$(mktemp)
    cat > "$tmpfile" <<- EOT
Images are ready for the commit at {{.Env._SHA}}.

To use the images, use the tag \`{{.Env._TAG}}\`.
EOT

    hub-comment -type build -template-file "$tmpfile"
}

push_images "$@"
