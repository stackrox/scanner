#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../.. && pwd)"
source "$ROOT/scripts/ci/deploy-postgres.sh"

set -euo pipefail

db_integration_tests() {
    info "Starting DB integration tests"

    deploy_postgres

    make db-integration-tests || touch FAIL

    info "Saving junit XML report"
    make generate-junit-reports || touch FAIL
    store_test_results junit-reports reports

    undeploy_postgres

    [[ ! -f FAIL ]] || die "DB integration tests failed"
}

db_integration_tests "$*"
