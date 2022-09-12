#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
source "$ROOT/scripts/ci/gcp.sh"
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

upload_db_dump() {
    local base_ref
    base_ref="$(get_base_ref)"
    if [[ "${base_ref}" == "master" ]]; then
        info "Starting DB dump upload"

        setup_gcp

        gsutil cp /tmp/postgres/pg-definitions.sql.gz gs://stackrox-scanner-ci-vuln-dump
    else
        info "This is not the master branch, so skipping..."
    fi
}

upload_db_dump "$*"
