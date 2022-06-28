#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../../../.. && pwd)"
source "$ROOT/scripts/ci/lib.sh"

set -euo pipefail

slim_e2e_tests() {
    info "Starting slim e2e tests"

    make slim-e2e-tests || touch FAIL

    info "Saving junit XML report"
    make generate-junit-reports || touch FAIL
    store_test_results junit-reports reports

    [[ ! -f FAIL ]] || die "Slim E2E tests failed"
}

slim_e2e_tests "$*"
