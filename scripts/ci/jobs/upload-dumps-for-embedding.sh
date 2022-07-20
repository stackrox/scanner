#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
source "$ROOT/scripts/ci/gcp.sh"
source "$ROOT/scripts/lib.sh"

set -euo pipefail

upload_dumps_for_embedding() {
#    if is_in_PR_context; then
#        info "In PR context. Skipping..."
#        return 0
#    fi

    info "Starting dumps upload"

    setup_gcp

    info "Extracting dumps"
    mkdir -p /tmp/vuln-dump
    zip /tmp/genesis-dump/dump.zip 'nvd/*' --copy --out /tmp/vuln-dump/nvd-definitions.zip
    zip /tmp/genesis-dump/dump.zip 'k8s/*' --copy --out /tmp/vuln-dump/k8s-definitions.zip
    zip /tmp/genesis-dump/dump.zip 'rhelv2/repository-to-cpe.json' --copy --out /tmp/vuln-dump/repo2cpe.zip

    info "Uploading dumps"
    # TODO: Fake for now...
    cmd=(echo "Would do")
    "${cmd[@]}" gsutil cp /tmp/vuln-dump/nvd-definitions.zip gs://stackrox-scanner-ci-vuln-dump
    "${cmd[@]}" gsutil cp /tmp/vuln-dump/k8s-definitions.zip gs://stackrox-scanner-ci-vuln-dump
    "${cmd[@]}" gsutil cp /tmp/vuln-dump/repo2cpe.zip gs://stackrox-scanner-ci-vuln-dump
}

upload_dumps_for_embedding "$*"
