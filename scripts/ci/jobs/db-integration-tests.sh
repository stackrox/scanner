#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

db_integration_tests() {
    info "Starting DB integration tests"

    touch /tmp/hold

    pid=$(run_postgres)

    make db-integration-tests || touch FAIL

    info "Saving junit XML report"
    make generate-junit-reports || touch FAIL
    store_test_results junit-reports reports

    [[ ! -f FAIL ]] || die "DB integration tests failed"

    # Terminate Postgres.
    kill -SIGINT "$pid"
}

db_integration_tests "$*"
