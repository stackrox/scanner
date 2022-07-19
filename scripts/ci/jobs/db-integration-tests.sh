#!/usr/bin/env bash

# Adapted from https://github.com/stackrox/stackrox/blob/master/scripts/ci/jobs/go-postgres-tests.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
source "$ROOT/scripts/ci/lib.sh"
set -euo pipefail

db_integration_tests() {
    info "Starting DB integration tests"

    initdb "${HOME}/data"
    pg_ctl -D "${HOME}/data" -l logfile -o "-k /tmp" start
    export PGHOST=/tmp
    createuser -s postgres

    make db-integration-tests || touch FAIL

    info "Saving junit XML report"
    make generate-junit-reports || touch FAIL
    store_test_results junit-reports reports

    [[ ! -f FAIL ]] || die "DB integration tests failed"
}

db_integration_tests "$*"
