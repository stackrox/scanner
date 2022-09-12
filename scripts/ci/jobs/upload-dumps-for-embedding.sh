#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
source "$ROOT/scripts/ci/gcp.sh"
source "$ROOT/scripts/lib.sh"

set -euo pipefail

upload_dumps_for_embedding() {
    local base_ref
    base_ref="$(get_base_ref)"
    if [[ "${base_ref}" == "master" ]]; then
        info "Starting dumps upload"

        setup_gcp

        info "Uploading dumps"
        gsutil cp /tmp/vuln-dump/nvd-definitions.zip gs://stackrox-scanner-ci-vuln-dump
        gsutil cp /tmp/vuln-dump/k8s-definitions.zip gs://stackrox-scanner-ci-vuln-dump
        gsutil cp /tmp/vuln-dump/repo2cpe.zip gs://stackrox-scanner-ci-vuln-dump
    else
        info "This is not the master branch, so skipping..."
    fi
}

upload_dumps_for_embedding "$*"
