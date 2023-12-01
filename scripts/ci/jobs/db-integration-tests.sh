#!/usr/bin/env bash

# Adapted from https://github.com/stackrox/stackrox/blob/master/scripts/ci/jobs/go-postgres-tests.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
# shellcheck source=../../../scripts/ci/lib.sh
source "$ROOT/scripts/ci/lib.sh"
# shellcheck source=../../../scripts/ci/postgres.sh
source "$ROOT/scripts/ci/postgres.sh"
set -euo pipefail

db_integration_tests() {
    info "Starting DB integration tests"

    start_postgres

    make db-integration-tests || touch FAIL

    info "Saving junit XML report"
    make generate-junit-reports || touch FAIL
    store_test_results junit-reports junit-reports

    [[ ! -f FAIL ]] || die "DB integration tests failed"
}

db_integration_tests "$*"
