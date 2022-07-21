#!/usr/bin/env bash

# Adapted from https://github.com/stackrox/stackrox/blob/master/scripts/ci/jobs/go-postgres-tests.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
source "$ROOT/scripts/ci/lib.sh"
set -euo pipefail

store_db_dump() {
    info "Storing DB dump"
    store_test_results /tmp/postgres postgres
}

store_db_dump "$*"
