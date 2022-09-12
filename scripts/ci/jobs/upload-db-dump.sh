#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
source "$ROOT/scripts/ci/gcp.sh"
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

upload_db_dump() {
    if is_in_PR_context; then
        info "Skipping upload, as this is a PR"
    fi
    if is_tagged; then
        info "Skipping upload, as this is a tag"
    fi

    info "Starting DB dump upload"

    setup_gcp

    gsutil cp /tmp/postgres/pg-definitions.sql.gz gs://stackrox-scanner-ci-vuln-dump
}

upload_db_dump "$*"
