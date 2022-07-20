#!/usr/bin/env bash

# Execute the build steps required to create the scanner-db image's bundle.tar.gz.
#
# Adapted from https://github.com/stackrox/stackrox/blob/master/.openshift-ci/build/build-central-db-bundle.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

openshift_ci_mods

create_db_bundle() {
    info "Creating scanner-db bundle.tar.gz"

    "$ROOT/image/db/rhel/create-bundle.sh" "$ROOT/image/scanner" "$ROOT/image/scanner/rhel"
}

db_bundle() {
    create_db_bundle
}

db_bundle
