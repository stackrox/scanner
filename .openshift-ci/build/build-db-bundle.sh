#!/usr/bin/env bash

# Execute the build steps required to create the scanner-db image's bundle.tar.gz.
#
# Adapted from https://github.com/stackrox/stackrox/blob/master/.openshift-ci/build/build-central-db-bundle.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

openshift_ci_mods

get_db_dump() {
    info "Retrieving DB dump"

    if is_in_PR_context && ! pr_has_label "generate-dumps-on-pr"; then
        setup_gcp

        echo "Label generate-dumps-on-pr not set. Pulling dumps from GCS bucket"
        gsutil cp gs://stackrox-scanner-ci-vuln-dump/pg-definitions.sql.gz image/db/dump/definitions.sql.gz
    else
        cp /tmp/postgres/pg-definitions.sql.gz image/db/dump/definitions.sql.gz
    fi
}

create_db_bundle() {
    info "Creating scanner-db bundle.tar.gz"

    "$ROOT/image/db/rhel/create-bundle.sh" "$ROOT/image/scanner" "$ROOT/image/scanner/rhel"
}

db_bundle() {
    get_db_dump

    create_db_bundle
}

db_bundle
